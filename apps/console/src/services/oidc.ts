/**
 * Specification Anchors: FEAT-009, NFR-029, screens.md, user-flow.md
 * OpenID Connect client for the console: Authorization Code flow with PKCE,
 * issuer discovery, ID-token signature verification against the provider JWKS,
 * and claim-derived session state.
 *
 * A console build without an issuer and client ID is unconfigured. It never
 * creates a token or auto-signs in.
 */

import {
  AuthErrorCode,
  OidcConfig,
  OidcTokens,
  UserProfile,
  UserRole,
} from '../types/auth';

const STORAGE_SESSION_KEY = 'aegis_auth_session';
const STORAGE_PKCE_VERIFIER_KEY = 'aegis_oidc_verifier';
const STORAGE_STATE_KEY = 'aegis_oidc_state';
const STORAGE_NONCE_KEY = 'aegis_oidc_nonce';

const IDLE_SESSION_MS = 15 * 60 * 1000;
const CLOCK_SKEW_SECONDS = 60;
const JWKS_MAX_AGE_MS = 5 * 60 * 1000;
const JWKS_STALE_GRACE_MS = 60 * 60 * 1000;

const VALID_ROLES: UserRole[] = ['admin', 'auditor', 'operator', 'viewer'];

export class OidcError extends Error {
  readonly code: AuthErrorCode;

  constructor(code: AuthErrorCode, message: string) {
    super(message);
    this.name = 'OidcError';
    this.code = code;
  }
}

interface OidcMetadata {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
}

interface JwtHeader {
  alg?: string;
  kid?: string;
  typ?: string;
}

interface Jwk extends JsonWebKey {
  kid?: string;
  alg?: string;
  use?: string;
}

interface JwksCacheEntry {
  uri: string;
  keys: Jwk[];
  fetchedAt: number;
}

let metadataCache: { authority: string; metadata: OidcMetadata } | null = null;
let jwksCache: JwksCacheEntry | null = null;

/** Reads identity configuration from the build environment. */
export function readOidcConfig(env: ImportMetaEnv): OidcConfig {
  const authority = (env.VITE_OIDC_AUTHORITY ?? '').trim().replace(/\/+$/, '');
  const clientId = (env.VITE_OIDC_CLIENT_ID ?? '').trim();
  const redirectUri =
    (env.VITE_OIDC_REDIRECT_URI ?? '').trim() ||
    (typeof window !== 'undefined' ? `${window.location.origin}/` : '');
  const scope = (env.VITE_OIDC_SCOPE ?? '').trim() || 'openid profile email roles';

  const configurationErrors: string[] = [];
  if (!authority) configurationErrors.push('VITE_OIDC_AUTHORITY');
  if (!clientId) configurationErrors.push('VITE_OIDC_CLIENT_ID');
  if (!redirectUri) configurationErrors.push('VITE_OIDC_REDIRECT_URI');

  return { authority, clientId, redirectUri, scope, configurationErrors };
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function decodeJsonSegment<T>(segment: string, label: string): T {
  try {
    return JSON.parse(new TextDecoder().decode(base64UrlDecode(segment))) as T;
  } catch {
    throw new OidcError('TOKEN_VERIFICATION', `The identity token ${label} is not valid JSON.`);
  }
}

/** Generates a cryptographically random base64url string (RFC 7636). */
function generateRandomString(bytes = 48): string {
  const array = new Uint8Array(bytes);
  window.crypto.getRandomValues(array);
  return base64UrlEncode(array).slice(0, 64);
}

async function computeSha256Challenge(codeVerifier: string): Promise<string> {
  const digest = await window.crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(codeVerifier)
  );
  return base64UrlEncode(new Uint8Array(digest));
}

interface AlgorithmSpec {
  importParams: RsaHashedImportParams | EcKeyImportParams;
  verifyParams: AlgorithmIdentifier | RsaPssParams | EcdsaParams;
  kty: string;
}

function algorithmSpec(alg: string): AlgorithmSpec {
  switch (alg) {
    case 'RS256':
      return {
        importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
        kty: 'RSA',
      };
    case 'RS384':
      return {
        importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
        verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
        kty: 'RSA',
      };
    case 'RS512':
      return {
        importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
        verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
        kty: 'RSA',
      };
    case 'PS256':
      return {
        importParams: { name: 'RSA-PSS', hash: 'SHA-256' },
        verifyParams: { name: 'RSA-PSS', saltLength: 32 },
        kty: 'RSA',
      };
    case 'PS384':
      return {
        importParams: { name: 'RSA-PSS', hash: 'SHA-384' },
        verifyParams: { name: 'RSA-PSS', saltLength: 48 },
        kty: 'RSA',
      };
    case 'PS512':
      return {
        importParams: { name: 'RSA-PSS', hash: 'SHA-512' },
        verifyParams: { name: 'RSA-PSS', saltLength: 64 },
        kty: 'RSA',
      };
    case 'ES256':
      return {
        importParams: { name: 'ECDSA', namedCurve: 'P-256' },
        verifyParams: { name: 'ECDSA', hash: 'SHA-256' },
        kty: 'EC',
      };
    case 'ES384':
      return {
        importParams: { name: 'ECDSA', namedCurve: 'P-384' },
        verifyParams: { name: 'ECDSA', hash: 'SHA-384' },
        kty: 'EC',
      };
    case 'ES512':
      return {
        importParams: { name: 'ECDSA', namedCurve: 'P-521' },
        verifyParams: { name: 'ECDSA', hash: 'SHA-512' },
        kty: 'EC',
      };
    default:
      throw new OidcError(
        'TOKEN_VERIFICATION',
        `The identity provider signed the token with unsupported algorithm ${alg}.`
      );
  }
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(url, init);
  } catch {
    throw new OidcError('DISCOVERY', 'The identity provider could not be reached.');
  }
  if (!response.ok) {
    throw new OidcError(
      'DISCOVERY',
      `The identity provider returned HTTP ${response.status} during discovery.`
    );
  }
  return (await response.json()) as T;
}

async function discover(authority: string): Promise<OidcMetadata> {
  if (metadataCache?.authority === authority) {
    return metadataCache.metadata;
  }

  const document = await fetchJson<{
    issuer?: string;
    authorization_endpoint?: string;
    token_endpoint?: string;
    jwks_uri?: string;
  }>(`${authority}/.well-known/openid-configuration`, {
    headers: { Accept: 'application/json' },
  });

  if (!document.authorization_endpoint || !document.token_endpoint || !document.jwks_uri) {
    throw new OidcError(
      'DISCOVERY',
      'The identity provider discovery document is missing required endpoints.'
    );
  }

  const metadata: OidcMetadata = {
    issuer: document.issuer ?? authority,
    authorizationEndpoint: document.authorization_endpoint,
    tokenEndpoint: document.token_endpoint,
    jwksUri: document.jwks_uri,
  };
  metadataCache = { authority, metadata };
  return metadata;
}

async function fetchJwks(uri: string): Promise<Jwk[]> {
  const now = Date.now();
  if (jwksCache?.uri === uri && now - jwksCache.fetchedAt < JWKS_MAX_AGE_MS) {
    return jwksCache.keys;
  }

  try {
    const document = await fetchJson<{ keys?: Jwk[] }>(uri, {
      headers: { Accept: 'application/json' },
    });
    if (!Array.isArray(document.keys) || document.keys.length === 0) {
      throw new OidcError('TOKEN_VERIFICATION', 'The identity provider published no signing keys.');
    }
    jwksCache = { uri, keys: document.keys, fetchedAt: now };
    return document.keys;
  } catch (error) {
    // A key-rotation fetch failure may fall back to a recently cached key set.
    if (jwksCache?.uri === uri && now - jwksCache.fetchedAt < JWKS_STALE_GRACE_MS) {
      return jwksCache.keys;
    }
    throw error;
  }
}

/** Decodes a JWT payload without trusting it. Verification happens separately. */
export function decodeJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split('.');
  if (parts.length !== 3) return {};
  try {
    return decodeJsonSegment<Record<string, unknown>>(parts[1], 'payload');
  } catch {
    return {};
  }
}

interface VerifyOptions {
  issuer: string;
  clientId: string;
  jwksUri: string;
  nonce?: string;
}

/**
 * Verifies an ID token's signature, issuer, audience, lifetime, and nonce.
 * Returns the trusted claim set.
 */
export async function verifyIdToken(
  idToken: string,
  options: VerifyOptions
): Promise<Record<string, unknown>> {
  const parts = idToken.split('.');
  if (parts.length !== 3) {
    throw new OidcError('TOKEN_VERIFICATION', 'The identity token is not a signed JWT.');
  }

  const header = decodeJsonSegment<JwtHeader>(parts[0], 'header');
  if (!header.alg || header.alg === 'none') {
    throw new OidcError('TOKEN_VERIFICATION', 'The identity token is unsigned.');
  }

  const spec = algorithmSpec(header.alg);
  const signature = base64UrlDecode(parts[2]);
  const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const keys = await fetchJwks(options.jwksUri);
  const candidates = keys.filter((key) => {
    if (key.kty !== spec.kty) return false;
    if (header.kid && key.kid && key.kid !== header.kid) return false;
    return true;
  });

  if (candidates.length === 0) {
    throw new OidcError(
      'TOKEN_VERIFICATION',
      'The identity token was signed with a key the provider does not publish.'
    );
  }

  let verified = false;
  for (const key of candidates) {
    try {
      const imported = await window.crypto.subtle.importKey(
        'jwk',
        key,
        spec.importParams,
        false,
        ['verify']
      );
      verified = await window.crypto.subtle.verify(
        spec.verifyParams,
        imported,
        signature as unknown as BufferSource,
        signingInput as unknown as BufferSource
      );
      if (verified) break;
    } catch {
      // Try the next published key; a key for another algorithm simply fails.
    }
  }

  if (!verified) {
    throw new OidcError('TOKEN_VERIFICATION', 'The identity token signature is not valid.');
  }

  const claims = decodeJsonSegment<Record<string, unknown>>(parts[1], 'payload');
  const now = Math.floor(Date.now() / 1000);
  const exp = typeof claims.exp === 'number' ? claims.exp : NaN;
  const nbf = typeof claims.nbf === 'number' ? claims.nbf : null;

  if (!Number.isFinite(exp) || exp + CLOCK_SKEW_SECONDS < now) {
    throw new OidcError('TOKEN_VERIFICATION', 'The identity token has expired.');
  }
  if (nbf !== null && nbf - CLOCK_SKEW_SECONDS > now) {
    throw new OidcError('TOKEN_VERIFICATION', 'The identity token is not valid yet.');
  }
  if (claims.iss !== options.issuer) {
    throw new OidcError('TOKEN_VERIFICATION', 'The identity token issuer does not match.');
  }

  const audience = claims.aud;
  const audiences = Array.isArray(audience) ? audience : [audience];
  if (!audiences.includes(options.clientId)) {
    throw new OidcError('TOKEN_VERIFICATION', 'The identity token was issued for another client.');
  }

  if (options.nonce !== undefined && claims.nonce !== options.nonce) {
    throw new OidcError('TOKEN_VERIFICATION', 'The identity token nonce does not match.');
  }

  return claims;
}

function claimRoles(claims: Record<string, unknown>, clientId: string): UserRole[] {
  const collected: string[] = [];

  if (Array.isArray(claims.roles)) {
    collected.push(...claims.roles.filter((role): role is string => typeof role === 'string'));
  }

  const realmAccess = claims.realm_access;
  if (realmAccess && typeof realmAccess === 'object') {
    const roles = (realmAccess as { roles?: unknown }).roles;
    if (Array.isArray(roles)) {
      collected.push(...roles.filter((role): role is string => typeof role === 'string'));
    }
  }

  const resourceAccess = claims.resource_access;
  if (resourceAccess && typeof resourceAccess === 'object') {
    const clientRoles = (resourceAccess as Record<string, { roles?: unknown }>)[clientId]?.roles;
    if (Array.isArray(clientRoles)) {
      collected.push(...clientRoles.filter((role): role is string => typeof role === 'string'));
    }
  }

  return Array.from(
    new Set(
      collected
        .map((role) => role.toLowerCase())
        .filter((role): role is UserRole => VALID_ROLES.includes(role as UserRole))
    )
  );
}

/** Builds the operator profile from verified claims only. */
export function profileFromClaims(
  claims: Record<string, unknown>,
  clientId: string,
  issuer: string
): UserProfile {
  const sub = typeof claims.sub === 'string' ? claims.sub : '';
  if (!sub) {
    throw new OidcError('TOKEN_VERIFICATION', 'The identity token has no subject claim.');
  }

  const roles = claimRoles(claims, clientId);
  if (roles.length === 0) {
    throw new OidcError(
      'ACCESS_DENIED',
      'Your account does not hold a console role (admin, operator, auditor, or viewer).'
    );
  }

  const preferredUsername =
    typeof claims.preferred_username === 'string' ? claims.preferred_username : undefined;
  const email = typeof claims.email === 'string' ? claims.email : '';
  const name =
    (typeof claims.name === 'string' && claims.name.trim()) ||
    preferredUsername ||
    email ||
    sub;

  return {
    sub,
    name,
    email,
    preferredUsername,
    roles,
    idp: typeof claims.iss === 'string' ? claims.iss : issuer,
    sessionExpiresAt: Date.now() + IDLE_SESSION_MS,
  };
}

export class OidcService {
  private readonly config: OidcConfig;

  constructor(config?: OidcConfig) {
    this.config = config ?? readOidcConfig(import.meta.env);
  }

  getConfig(): OidcConfig {
    return this.config;
  }

  get isConfigured(): boolean {
    return this.config.configurationErrors.length === 0;
  }

  private assertConfigured(): void {
    if (!this.isConfigured) {
      throw new OidcError(
        'CONFIGURATION',
        `Missing identity configuration: ${this.config.configurationErrors.join(', ')}.`
      );
    }
  }

  /** Starts Authorization Code Flow with PKCE at the configured provider. */
  async startAuthorizationRedirect(): Promise<void> {
    this.assertConfigured();
    const metadata = await discover(this.config.authority);
    const codeVerifier = generateRandomString();
    const codeChallenge = await computeSha256Challenge(codeVerifier);
    const state = generateRandomString();
    const nonce = generateRandomString();

    sessionStorage.setItem(STORAGE_PKCE_VERIFIER_KEY, codeVerifier);
    sessionStorage.setItem(STORAGE_STATE_KEY, state);
    sessionStorage.setItem(STORAGE_NONCE_KEY, nonce);

    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: this.config.scope,
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    window.location.assign(`${metadata.authorizationEndpoint}?${params.toString()}`);
  }

  /** Exchanges the authorization code and verifies the returned ID token. */
  async handleCallback(
    searchParams: URLSearchParams
  ): Promise<{ user: UserProfile; tokens: OidcTokens } | null> {
    const code = searchParams.get('code');
    if (!code) return null;
    this.assertConfigured();

    const returnedState = searchParams.get('state');
    const savedState = sessionStorage.getItem(STORAGE_STATE_KEY);
    const codeVerifier = sessionStorage.getItem(STORAGE_PKCE_VERIFIER_KEY);
    const nonce = sessionStorage.getItem(STORAGE_NONCE_KEY) ?? undefined;

    if (!savedState || returnedState !== savedState || !codeVerifier) {
      throw new OidcError(
        'CALLBACK',
        'The sign-in response could not be matched to this console session. Start sign-in again.'
      );
    }

    const metadata = await discover(this.config.authority);
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      code,
      code_verifier: codeVerifier,
    });

    let response: Response;
    try {
      response = await fetch(metadata.tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
      });
    } catch {
      throw new OidcError('TOKEN_EXCHANGE', 'The identity provider could not be reached.');
    }

    if (!response.ok) {
      throw new OidcError(
        'TOKEN_EXCHANGE',
        `The identity provider rejected the authorization code with HTTP ${response.status}.`
      );
    }

    const data = (await response.json()) as {
      id_token?: string;
      access_token?: string;
      refresh_token?: string;
      expires_in?: number;
      token_type?: string;
      scope?: string;
    };

    if (!data.id_token || !data.access_token) {
      throw new OidcError(
        'TOKEN_EXCHANGE',
        'The identity provider did not return an ID token and access token.'
      );
    }

    const claims = await verifyIdToken(data.id_token, {
      issuer: metadata.issuer,
      clientId: this.config.clientId,
      jwksUri: metadata.jwksUri,
      nonce,
    });
    const user = profileFromClaims(claims, this.config.clientId, metadata.issuer);

    const tokens: OidcTokens = {
      idToken: data.id_token,
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresIn: typeof data.expires_in === 'number' ? data.expires_in : 0,
      tokenType: data.token_type ?? 'Bearer',
      scope: data.scope ?? this.config.scope,
    };

    sessionStorage.removeItem(STORAGE_PKCE_VERIFIER_KEY);
    sessionStorage.removeItem(STORAGE_STATE_KEY);
    sessionStorage.removeItem(STORAGE_NONCE_KEY);

    this.saveSession(user, tokens);
    return { user, tokens };
  }

  saveSession(user: UserProfile, tokens: OidcTokens): void {
    try {
      sessionStorage.setItem(STORAGE_SESSION_KEY, JSON.stringify({ user, tokens }));
    } catch {
      // Storage may be blocked; the in-memory session still works for this tab.
    }
  }

  getSavedSession(): { user: UserProfile; tokens: OidcTokens } | null {
    try {
      const raw = sessionStorage.getItem(STORAGE_SESSION_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw) as { user?: UserProfile; tokens?: OidcTokens };
      if (!parsed.user || !parsed.tokens?.idToken || !parsed.tokens.accessToken) {
        this.clearSession();
        return null;
      }
      if (!this.isTokenFresh(parsed.tokens.idToken)) {
        this.clearSession();
        return null;
      }
      return { user: parsed.user, tokens: parsed.tokens };
    } catch {
      return null;
    }
  }

  getAccessToken(): string | null {
    return this.getSavedSession()?.tokens.accessToken ?? null;
  }

  /** True while the ID token's own expiry leaves it usable. */
  isTokenFresh(idToken: string): boolean {
    const claims = decodeJwtPayload(idToken);
    const exp = claims.exp;
    if (typeof exp !== 'number') return false;
    return exp - CLOCK_SKEW_SECONDS > Math.floor(Date.now() / 1000);
  }

  clearSession(): void {
    try {
      sessionStorage.removeItem(STORAGE_SESSION_KEY);
      sessionStorage.removeItem(STORAGE_PKCE_VERIFIER_KEY);
      sessionStorage.removeItem(STORAGE_STATE_KEY);
      sessionStorage.removeItem(STORAGE_NONCE_KEY);
    } catch {
      // Ignore storage failures during sign-out.
    }
  }
}

export const oidcService = new OidcService();
