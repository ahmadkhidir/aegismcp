#!/usr/bin/env python3
"""Verify the local OIDC provider, the gateway's token validation, and console role access.

The check is a black-box client of the running stack, not a test double: it drives the real
Authorization Code flow with PKCE against the pinned Keycloak realm, completes the real TOTP
enrolment the realm demands, exchanges the code at the real token endpoint, and presents the
resulting access token to the packaged gateway.

What it proves, per role defined in the imported realm:

  * the console's public client completes Authorization Code Flow with PKCE (RFC 7636, S256);
  * console access requires a second factor: valid credentials alone never return an
    authorization code, they return the provider's one-time-password enrolment, and a later
    sign-in returns the one-time-password challenge;
  * the issued ID token carries the provider issuer, the console client as audience, the nonce
    the console sent, and the operator's role, which is the claim set the console maps into RBAC;
  * the access token is a real signed token for the gateway audience: the gateway accepts it and
    rejects a token whose signature it cannot verify;
  * role-based access holds at the gateway: every role reaches the fleet read, while a viewer is
    forbidden the policy surface that admin, operator, and auditor may read.

Specification anchors: FEAT-009, NFR-029, operations.md "Enterprise Identity Provider (SSO /
OIDC) Federation".

Environment:
  OIDC_ISSUER            the issuer the provider publishes and every token must carry
  OIDC_PUBLIC_URL        browser-facing base URL of the provider
  OIDC_REALM             realm name
  OIDC_CONSOLE_CLIENT_ID public PKCE client registered for the console
  OIDC_REDIRECT_URI      redirect URI registered on that client
  OIDC_AUDIENCE          audience value the gateway requires on access tokens
  OIDC_INTERNAL_URL      container-network base URL used for the OAuth calls
  GATEWAY_URL            container-network base URL of the gateway
  OIDC_REALM_FILE        path to the imported realm export
  OIDC_ADMIN_USERNAME    local provider administrator used to reset the declared user state
  OIDC_ADMIN_PASSWORD    password of that administrator
  OIDC_<ROLE>_USER_PASSWORD  password of the console user holding <ROLE>

Exit status: 0 when every check passes, 1 otherwise.
"""

import base64
import hashlib
import hmac
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

FLEET_READ_PATH = "/api/v1/system/status"
POLICY_READ_PATH = "/api/v1/policies"
POLICY_READ_ROLES = ("admin", "operator", "auditor")
ROLE_ORDER = ("admin", "operator", "auditor", "viewer")
STARTUP_TIMEOUT_SECONDS = 90
TOTP_DIGITS = 6
TOTP_PERIOD_SECONDS = 30

OTP_CHALLENGE_FORM = "kc-otp-login-form"
OTP_CONFIG_FORM = "kc-totp-settings-form"
LOGIN_FORM = "kc-form-login"
MANUAL_LINK = re.compile(r'href="([^"]*mode=manual[^"]*)"')
DISPLAYED_SECRET = re.compile(r'id="kc-totp-secret[^"]*"[^>]*>\s*([A-Za-z0-9 ]+?)\s*<', re.S)
HIDDEN_SECRET = re.compile(r'name="totpSecret"[^>]*value="([^"]+)"')
FORM_ACTION = re.compile(r'\baction="([^"]+)"', re.S)


class SmokeFailure(Exception):
    """Raised when a check produces a result the stack must not produce."""


def log(message):
    print("oidc-smoke: " + message, flush=True)


def fail(message):
    raise SmokeFailure(message)


def expect(condition, message):
    if not condition:
        fail(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Leaves redirect responses to the caller so the check can read the Location header."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Session:
    """Minimal cookie session for the login flow.

    The provider marks its authentication cookies `Secure` with `SameSite=None`, as it must for
    cross-site browser use. Browsers accept such cookies on the http://localhost origin because
    localhost is a trustworthy origin, while the standard library withholds them from a plain HTTP
    request. The check therefore carries the cookie values itself, which reproduces browser
    behavior for the local issuer without weakening the provider.
    """

    def __init__(self):
        self.opener = urllib.request.build_opener(NoRedirect())
        self.cookies = {}

    def request(self, url, data=None, headers=None):
        sent = dict(headers or {})
        if self.cookies:
            sent["Cookie"] = "; ".join("%s=%s" % item for item in self.cookies.items())
        status, response_headers, body = send(self.opener, url, data, sent)
        for raw in response_headers.get_all("Set-Cookie") or []:
            name_value = raw.split(";", 1)[0]
            if "=" in name_value:
                name, value = name_value.split("=", 1)
                name = name.strip()
                value = value.strip()
                if value in ("", "EXPIRED"):
                    self.cookies.pop(name, None)
                else:
                    self.cookies[name] = value
        return status, response_headers, body


def send(opener, url, data=None, headers=None):
    """Performs one request and returns (status, headers, body bytes), never raising on 4xx/5xx."""
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode("utf-8")
    prepared = urllib.request.Request(url, data=body, headers=headers or {})
    if body is not None:
        prepared.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with opener.open(prepared, timeout=20) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read()


def get_json(url):
    request_headers = {"Accept": "application/json"}
    try:
        with urllib.request.urlopen(
            urllib.request.Request(url, headers=request_headers), timeout=20
        ) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        fail("GET %s answered HTTP %s" % (url, error.code))
    except urllib.error.URLError as error:
        fail("GET %s did not answer: %s" % (url, error.reason))


def base64url_decode(value):
    padded = value.replace("-", "+").replace("_", "/")
    return base64.b64decode(padded + "=" * ((4 - len(padded) % 4) % 4))


def base64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_segment(token, index):
    parts = token.split(".")
    expect(len(parts) == 3, "the token is not a three-segment JWT")
    return json.loads(base64url_decode(parts[index]).decode("utf-8"))


def totp_counter():
    return int(time.time()) // TOTP_PERIOD_SECONDS


def totp(secret, counter=None):
    """Computes a TOTP value for a base32 seed (RFC 6238, SHA-1, 6 digits)."""
    key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
    counter = totp_counter() if counter is None else counter
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (
        int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    ) % (10 ** TOTP_DIGITS)
    return str(code).zfill(TOTP_DIGITS)


def fresh_totp(secret, after_counter):
    """Returns a TOTP value from a later window.

    The provider refuses a code it has already accepted, so a second sign-in that reuses the
    enrolment code inside the same thirty-second window would be rejected for the wrong reason.
    """
    counter = totp_counter()
    if after_counter is not None and counter <= after_counter:
        time.sleep(TOTP_PERIOD_SECONDS - (time.time() % TOTP_PERIOD_SECONDS) + 1)
        counter = totp_counter()
    return totp(secret, counter), counter


def internal_url(url, env):
    """Rewrites a provider URL onto the container-network address the check can reach."""
    parsed = urllib.parse.urlsplit(url)
    public = urllib.parse.urlsplit(env["OIDC_PUBLIC_URL"])
    if parsed.netloc == public.netloc:
        internal = urllib.parse.urlsplit(env["OIDC_INTERNAL_URL"])
        return urllib.parse.urlunsplit(
            (internal.scheme, internal.netloc, parsed.path, parsed.query, parsed.fragment)
        )
    return url


def form_action(page, form_id, env):
    """Returns the action URL of the named provider form, addressed on the internal network."""
    tag = re.compile(r'<form\b[^>]*id="%s"[^>]*>' % re.escape(form_id), re.S).search(page)
    expect(tag is not None, "the provider page has no %s form" % form_id)
    action = FORM_ACTION.search(tag.group(0))
    expect(action is not None, "the %s form declares no action" % form_id)
    return internal_url(html.unescape(action.group(1)), env)


def realm_role_users(realm):
    """Maps each console role to the realm user that holds it."""
    by_role = {}
    for user in realm.get("users", []):
        for role in user.get("realmRoles", []):
            if role in ROLE_ORDER and role not in by_role:
                by_role[role] = user
    missing = [role for role in ROLE_ORDER if role not in by_role]
    expect(not missing, "the realm defines no user for role(s): %s" % ", ".join(missing))
    return by_role


def password_for(role, env):
    """Reads a console user's password from the environment compose injects from .env."""
    variable = "OIDC_%s_USER_PASSWORD" % role.upper()
    value = env.get(variable)
    expect(value, "environment variable %s is required; run bootstrap-oidc.mjs init" % variable)
    return value


def authorization_url(env, metadata, code_verifier, state, nonce):
    challenge = base64url_encode(hashlib.sha256(code_verifier.encode("ascii")).digest())
    query = urllib.parse.urlencode(
        {
            "client_id": env["OIDC_CONSOLE_CLIENT_ID"],
            "redirect_uri": env["OIDC_REDIRECT_URI"],
            "response_type": "code",
            "scope": "openid profile email roles",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return internal_url(metadata["authorization_endpoint"], env) + "?" + query


def authorization_code(status, headers, env, state):
    """Reads the authorization response redirect the provider issues once the user is signed in."""
    expect(
        status in (302, 303),
        "the provider answered HTTP %s instead of redirecting with an authorization code; "
        "the sign-in did not complete" % status,
    )
    location = headers.get("Location")
    expect(location is not None, "the provider redirected without a Location header")
    parsed = urllib.parse.urlsplit(location)
    target = parsed.scheme + "://" + parsed.netloc + parsed.path
    expect(
        target == env["OIDC_REDIRECT_URI"],
        "the authorization response targeted %s, not the registered redirect URI" % target,
    )
    parameters = urllib.parse.parse_qs(parsed.query)
    expect("error" not in parameters, "the provider rejected the sign-in: %s" % parameters.get("error"))
    expect("state" in parameters and parameters["state"][0] == state,
           "the authorization response state does not match the request")
    expect("code" in parameters, "the authorization response carried no authorization code")
    return parameters["code"][0]


def settle(session, status, headers, body, env):
    """Follows redirects the provider issues between its own steps.

    Keycloak answers a completed step with a redirect to the next authentication step. A redirect
    that leaves the provider is the authorization response for the console and is returned as is.
    """
    public_netloc = urllib.parse.urlsplit(env["OIDC_PUBLIC_URL"]).netloc
    for _ in range(10):
        if status not in (302, 303):
            return status, headers, body
        location = headers.get("Location")
        expect(location is not None, "the provider redirected without a Location header")
        target = urllib.parse.urlsplit(location)
        if target.netloc and target.netloc != public_netloc:
            return status, headers, body
        status, headers, body = session.request(internal_url(location, env))
    fail("the provider issued more than ten consecutive redirects during sign-in")


def enrol_second_factor(session, page, env, username):
    """Completes the provider's one-time-password enrolment and returns the seed and response."""
    manual = MANUAL_LINK.search(page)
    expect(manual is not None,
           "the enrolment page offers no manual seed, so the check cannot scan the QR code")
    status, headers, manual_page = session.request(
        internal_url(html.unescape(manual.group(1)), env)
    )
    status, headers, manual_page = settle(session, status, headers, manual_page, env)
    expect(status == 200, "the manual enrolment page answered HTTP %s" % status)
    body = manual_page.decode("utf-8", "replace")
    shown = DISPLAYED_SECRET.search(body)
    expect(shown is not None, "the manual enrolment page displays no seed")
    seed = re.sub(r"\s+", "", shown.group(1)).upper()
    hidden = HIDDEN_SECRET.search(body)
    expect(hidden is not None, "the enrolment form carries no provider secret field")
    counter = totp_counter()
    fields = {"totp": totp(seed, counter), "totpSecret": html.unescape(hidden.group(1)),
              "userLabel": username}
    status, headers, page = session.request(form_action(body, OTP_CONFIG_FORM, env), fields)
    status, headers, page = settle(session, status, headers, page, env)
    return seed, counter, status, headers, page


def sign_in(env, metadata, user, password, seed=None, consumed_counter=None):
    """Signs a real user in through the console client.

    Returns the authorization code, its PKCE verifier, the nonce, the enrolled seed, and the
    one-time-password window the sign-in consumed. A user who has not enrolled a second factor is
    walked through the provider's enrolment; a user who has is challenged for the one-time code.
    Either way no authorization code exists until the second factor is satisfied.
    """
    session = Session()
    code_verifier = base64url_encode(os.urandom(48))
    state = base64url_encode(os.urandom(16))
    nonce = base64url_encode(os.urandom(16))

    status, headers, page = session.request(
        authorization_url(env, metadata, code_verifier, state, nonce)
    )
    status, headers, page = settle(session, status, headers, page, env)
    expect(status == 200, "the authorization request answered HTTP %s, not the login page" % status)
    login_page = page.decode("utf-8", "replace")
    expect('id="%s"' % LOGIN_FORM in login_page,
           "the authorization endpoint did not serve the login form")

    status, headers, page = session.request(
        form_action(login_page, LOGIN_FORM, env),
        {"username": user["username"], "password": password},
    )
    status, headers, page = settle(session, status, headers, page, env)
    expect(
        status == 200,
        "valid credentials completed the sign-in without a second factor; console access would "
        "not require multi-factor authentication",
    )
    body = page.decode("utf-8", "replace")

    if 'id="%s"' % OTP_CONFIG_FORM in body:
        seed, counter, status, headers, page = enrol_second_factor(
            session, body, env, user["username"]
        )
        code = authorization_code(status, headers, env, state)
        log("pass: %s enrolled a one-time-password factor before the provider issued a session"
            % user["username"])
        return code, code_verifier, nonce, seed, counter

    expect('id="%s"' % OTP_CHALLENGE_FORM in body,
           "valid credentials produced neither a one-time-password challenge nor enrolment")
    expect(seed is not None,
           "the provider demanded a one-time code but the check holds no enrolled seed")
    code_value, counter = fresh_totp(seed, consumed_counter)
    status, headers, page = session.request(
        form_action(body, OTP_CHALLENGE_FORM, env), {"otp": code_value}
    )
    status, headers, page = settle(session, status, headers, page, env)
    expect(status != 200,
           "the one-time-password step re-served a page instead of completing; the code was "
           "rejected")
    code = authorization_code(status, headers, env, state)
    log("pass: %s answered the one-time-password challenge before the provider issued a session"
        % user["username"])
    return code, code_verifier, nonce, seed, counter


def exchange_code(metadata, env, code, code_verifier):
    token_url = internal_url(metadata["token_endpoint"], env)
    status, _, body = Session().request(
        token_url,
        {
            "grant_type": "authorization_code",
            "client_id": env["OIDC_CONSOLE_CLIENT_ID"],
            "redirect_uri": env["OIDC_REDIRECT_URI"],
            "code": code,
            "code_verifier": code_verifier,
        },
    )
    expect(status == 200, "the token endpoint answered HTTP %s for the console client" % status)
    tokens = json.loads(body.decode("utf-8"))
    expect("id_token" in tokens, "the token response carried no ID token")
    expect("access_token" in tokens, "the token response carried no access token")
    return tokens


def admin_call(env, method, path, token, body=None):
    url = env["OIDC_INTERNAL_URL"].rstrip("/") + "/admin/realms/" + env["OIDC_REALM"] + path
    headers = {"Accept": "application/json", "Authorization": "Bearer " + token}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    prepared = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(prepared, timeout=20) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        fail("the provider admin API answered HTTP %s for %s %s" % (error.code, method, path))
    except urllib.error.URLError as error:
        fail("the provider admin API did not answer: %s" % error.reason)


def admin_token(env):
    """Obtains a provider administrator token for the local stack.

    The check resets each console user's second factor before enrolling it again, so a repeated
    run starts from the state the realm import declares instead of depending on a previous run.
    """
    url = env["OIDC_INTERNAL_URL"].rstrip("/") + "/realms/master/protocol/openid-connect/token"
    status, _, body = Session().request(
        url,
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": env["OIDC_ADMIN_USERNAME"],
            "password": env["OIDC_ADMIN_PASSWORD"],
        },
    )
    expect(status == 200, "the provider rejected the administrator sign-in with HTTP %s" % status)
    return json.loads(body.decode("utf-8"))["access_token"]


def reset_second_factor(env, token, username):
    status, found = admin_call(
        env, "GET", "/users?exact=true&username=" + urllib.parse.quote(username), token
    )
    expect(status == 200 and found, "the provider has no user %s" % username)
    user_id = found[0]["id"]
    _, credentials = admin_call(env, "GET", "/users/%s/credentials" % user_id, token)
    for credential in credentials or []:
        if credential.get("type") == "otp":
            admin_call(env, "DELETE", "/users/%s/credentials/%s" % (user_id, credential["id"]), token)
    admin_call(env, "PUT", "/users/%s" % user_id, token, {"requiredActions": ["CONFIGURE_TOTP"]})


def gateway_call(env, path, token):
    url = env["GATEWAY_URL"].rstrip("/") + path
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=20) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except urllib.error.URLError as error:
        fail("the gateway at %s did not answer: %s" % (env["GATEWAY_URL"], error.reason))


def tamper(token):
    """Flips the last signature byte so the signature no longer verifies."""
    parts = token.split(".")
    signature = bytearray(base64url_decode(parts[2]))
    signature[-1] ^= 0x01
    return ".".join([parts[0], parts[1], base64url_encode(bytes(signature))])


def wait_for_provider(env):
    discovery_url = (
        env["OIDC_INTERNAL_URL"].rstrip("/")
        + "/realms/"
        + env["OIDC_REALM"]
        + "/.well-known/openid-configuration"
    )
    deadline = time.time() + STARTUP_TIMEOUT_SECONDS
    last_error = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(discovery_url, timeout=5) as response:
                if response.status == 200:
                    return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, ValueError) as error:
            last_error = error
        time.sleep(2)
    fail("the provider did not publish its discovery document within %ss (%s)"
         % (STARTUP_TIMEOUT_SECONDS, last_error))


def main():
    env = dict(os.environ)
    for key in (
        "OIDC_ISSUER",
        "OIDC_PUBLIC_URL",
        "OIDC_REALM",
        "OIDC_CONSOLE_CLIENT_ID",
        "OIDC_REDIRECT_URI",
        "OIDC_AUDIENCE",
        "OIDC_INTERNAL_URL",
        "GATEWAY_URL",
        "OIDC_REALM_FILE",
        "OIDC_ADMIN_USERNAME",
        "OIDC_ADMIN_PASSWORD",
        "OIDC_ADMIN_USER_PASSWORD",
        "OIDC_OPERATOR_USER_PASSWORD",
        "OIDC_AUDITOR_USER_PASSWORD",
        "OIDC_VIEWER_USER_PASSWORD",
    ):
        expect(env.get(key), "environment variable %s is required" % key)

    with open(env["OIDC_REALM_FILE"], encoding="utf-8") as handle:
        realm = json.load(handle)

    metadata = wait_for_provider(env)
    expect(
        metadata["issuer"] == env["OIDC_ISSUER"],
        "the provider issuer %s does not match the configured issuer %s"
        % (metadata["issuer"], env["OIDC_ISSUER"]),
    )
    expect("jwks_uri" in metadata, "the discovery document publishes no JWKS endpoint")
    jwks = get_json(internal_url(metadata["jwks_uri"], env))
    signing_keys = [key for key in jwks.get("keys", []) if key.get("use", "sig") == "sig"]
    expect(signing_keys, "the provider published no signing keys")
    log("pass: provider %s publishes discovery and %d signing key(s)"
        % (metadata["issuer"], len(signing_keys)))

    clients = {client["clientId"]: client for client in realm.get("clients", [])}
    console = clients.get(env["OIDC_CONSOLE_CLIENT_ID"])
    expect(console is not None, "the realm has no client %s" % env["OIDC_CONSOLE_CLIENT_ID"])
    expect(console.get("publicClient") is True, "the console client is not public")
    expect(
        console.get("attributes", {}).get("pkce.code.challenge.method") == "S256",
        "the console client does not require PKCE with SHA-256",
    )
    expect(
        any(
            env["OIDC_REDIRECT_URI"].startswith(registered.replace("*", ""))
            for registered in console.get("redirectUris", [])
        ),
        "the redirect URI %s is not registered on the console client" % env["OIDC_REDIRECT_URI"],
    )
    gateway_audiences = [
        mapper.get("config", {}).get("included.custom.audience")
        for mapper in console.get("protocolMappers", [])
        if mapper.get("protocolMapper") == "oidc-audience-mapper"
    ]
    expect(env["OIDC_AUDIENCE"] in gateway_audiences,
           "the console client issues no access token for the gateway audience %s"
           % env["OIDC_AUDIENCE"])
    log("pass: console client %s is public, PKCE S256, redirect and gateway audience registered"
        % env["OIDC_CONSOLE_CLIENT_ID"])

    users = realm_role_users(realm)
    token = admin_token(env)
    for role in ROLE_ORDER:
        reset_second_factor(env, token, users[role]["username"])
    log("pass: every console user starts from the realm's declared state with no enrolled factor")

    expect(
        gateway_call(env, FLEET_READ_PATH, None) == 401,
        "the gateway answered an unauthenticated fleet read without 401",
    )
    log("pass: gateway rejects an unauthenticated fleet read with 401")

    tokens_by_role = {}
    seeds_by_role = {}
    counters_by_role = {}
    for role in ROLE_ORDER:
        user = users[role]
        code, code_verifier, nonce, seed, counter = sign_in(
            env, metadata, user, password_for(role, env)
        )
        seeds_by_role[role] = seed
        counters_by_role[role] = counter
        tokens = exchange_code(metadata, env, code, code_verifier)

        id_claims = decode_segment(tokens["id_token"], 1)
        access_claims = decode_segment(tokens["access_token"], 1)
        expect(id_claims.get("iss") == env["OIDC_ISSUER"],
               "the ID token for %s carries issuer %s" % (role, id_claims.get("iss")))
        audiences = id_claims.get("aud")
        audiences = audiences if isinstance(audiences, list) else [audiences]
        expect(env["OIDC_CONSOLE_CLIENT_ID"] in audiences,
               "the ID token for %s was not issued for the console client" % role)
        expect(id_claims.get("nonce") == nonce,
               "the ID token for %s does not carry the nonce the console sent" % role)
        roles = id_claims.get("roles")
        expect(isinstance(roles, list) and role in roles,
               "the ID token for %s does not carry the %s role in its roles claim" % (role, role))
        access_audiences = access_claims.get("aud")
        access_audiences = access_audiences if isinstance(access_audiences, list) else [access_audiences]
        expect(env["OIDC_AUDIENCE"] in access_audiences,
               "the access token for %s does not carry the gateway audience %s"
               % (role, env["OIDC_AUDIENCE"]))

        expect(gateway_call(env, FLEET_READ_PATH, tokens["access_token"]) == 200,
               "the gateway rejected the verified %s access token on the fleet read" % role)
        log("pass: gateway accepted the verified %s access token on the fleet read" % role)
        tokens_by_role[role] = tokens["access_token"]

    # A second sign-in with the enrolled factor proves MFA is enforced after enrolment, not only
    # during the first-run setup.
    code, code_verifier, _, _, _ = sign_in(
        env, metadata, users["admin"], password_for("admin", env),
        seeds_by_role["admin"], counters_by_role["admin"]
    )
    expect(exchange_code(metadata, env, code, code_verifier)["access_token"] is not None,
           "the second sign-in with the enrolled factor returned no access token")
    log("pass: an enrolled operator is challenged for the one-time code on the next sign-in")

    for role in POLICY_READ_ROLES:
        expect(gateway_call(env, POLICY_READ_PATH, tokens_by_role[role]) == 200,
               "the gateway forbade the policy read to the %s role" % role)
    log("pass: policy read allowed for %s" % ", ".join(POLICY_READ_ROLES))
    expect(gateway_call(env, POLICY_READ_PATH, tokens_by_role["viewer"]) == 403,
           "the gateway allowed the viewer role onto the policy surface")
    log("pass: policy read forbidden to the viewer role with 403")

    expect(gateway_call(env, FLEET_READ_PATH, tamper(tokens_by_role["admin"])) == 401,
           "the gateway accepted an access token whose signature does not verify")
    log("pass: gateway rejects a tampered signature with 401")

    log("all checks passed")


if __name__ == "__main__":
    try:
        main()
    except SmokeFailure as error:
        print("oidc-smoke: FAILED: %s" % error, file=sys.stderr)
        sys.exit(1)
