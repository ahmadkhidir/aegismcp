/**
 * Specification Anchors: FEAT-009, NFR-029, screens.md, user-personas.md
 * Standards-compliant OpenID Connect (OIDC) client with RFC 7636 PKCE Authorization Code flow
 * and enterprise persona mock provider for local development & automated testing.
 */

import { OidcConfig, OidcTokens, UserProfile, UserRole } from '../types/auth';

const STORAGE_SESSION_KEY = 'aegis_auth_session';
const STORAGE_PKCE_VERIFIER_KEY = 'aegis_oidc_verifier';
const STORAGE_STATE_KEY = 'aegis_oidc_state';
const STORAGE_NONCE_KEY = 'aegis_oidc_nonce';

/** Predefined enterprise personas according to docs/AegisMCP/user-personas.md */
export const ENTERPRISE_PERSONAS: Record<string, {
  name: string;
  email: string;
  roles: UserRole[];
  title: string;
  sub: string;
}> = {
  elena: {
    sub: 'spiffe://aegis.internal/secops/users/elena.rostova',
    name: 'Elena Rostova',
    email: 'elena.rostova@aegis.internal',
    roles: ['admin', 'operator', 'auditor'],
    title: 'SecOps Admin',
  },
  priya: {
    sub: 'spiffe://aegis.internal/compliance/users/priya.sharma',
    name: 'Priya Sharma',
    email: 'priya.sharma@aegis.internal',
    roles: ['auditor'],
    title: 'CISO / Auditor',
  },
  marcus: {
    sub: 'spiffe://aegis.internal/platform/users/marcus.vance',
    name: 'Marcus Vance',
    email: 'marcus.vance@aegis.internal',
    roles: ['operator'],
    title: 'Platform Engineer',
  },
  david: {
    sub: 'spiffe://aegis.internal/developer/users/david.chen',
    name: 'David Chen',
    email: 'david.chen@aegis.internal',
    roles: ['viewer'],
    title: 'AI Developer',
  },
};

/** Base64URL string encoder conforming to RFC 7636 */
function base64UrlEncode(arrayBuffer: ArrayBuffer | Uint8Array): string {
  const bytes = arrayBuffer instanceof Uint8Array ? arrayBuffer : new Uint8Array(arrayBuffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/** Generate cryptographically random string */
function generateRandomString(length = 43): string {
  const array = new Uint8Array(length);
  window.crypto.getRandomValues(array);
  return base64UrlEncode(array).slice(0, length);
}

/** Compute SHA-256 code challenge from verifier */
async function computeSha256Challenge(codeVerifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await window.crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(digest);
}

/** Decode JWT payload */
export function parseJwtPayload(token: string): Record<string, unknown> {
  try {
    const parts = token.split('.');
    if (parts.length < 2) return {};
    const base64Url = parts[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch {
    return {};
  }
}

/** Create signed-shape mock JWT for local or testing use */
export function createMockJwt(claims: Record<string, unknown>): string {
  const header = { alg: 'RS256', typ: 'JWT', kid: 'aegis-dev-key' };
  const encodedHeader = base64UrlEncode(new TextEncoder().encode(JSON.stringify(header)));
  const encodedPayload = base64UrlEncode(new TextEncoder().encode(JSON.stringify(claims)));
  const dummySignature = base64UrlEncode(new TextEncoder().encode('mock_signature_bytes_verified'));
  return `${encodedHeader}.${encodedPayload}.${dummySignature}`;
}

export class OidcService {
  private config: OidcConfig;

  constructor() {
    const authority = (import.meta.env.VITE_OIDC_AUTHORITY as string | undefined) || '';
    const isMock = !authority || authority.toLowerCase() === 'mock';

    this.config = {
      authority,
      clientId: (import.meta.env.VITE_OIDC_CLIENT_ID as string | undefined) || 'aegismcp-console',
      redirectUri:
        (import.meta.env.VITE_OIDC_REDIRECT_URI as string | undefined) ||
        (typeof window !== 'undefined' ? `${window.location.origin}/` : 'http://localhost:5173/'),
      scope: (import.meta.env.VITE_OIDC_SCOPE as string | undefined) || 'openid profile email roles',
      isMock,
    };
  }

  getConfig(): OidcConfig {
    return this.config;
  }

  /**
   * Generates mock tokens and user profile for local developer personas
   */
  createMockSession(personaKey = 'elena'): { user: UserProfile; tokens: OidcTokens } {
    const persona = ENTERPRISE_PERSONAS[personaKey] || ENTERPRISE_PERSONAS.elena;
    const nowSec = Math.floor(Date.now() / 1000);
    const expSec = nowSec + 3600; // 1 hour token lifetime

    const idTokenClaims = {
      sub: persona.sub,
      name: persona.name,
      email: persona.email,
      preferred_username: persona.email.split('@')[0],
      roles: persona.roles,
      realm_access: { roles: persona.roles },
      iss: this.config.isMock ? 'https://auth.aegismcp.mock/realms/aegis' : this.config.authority,
      aud: this.config.clientId,
      iat: nowSec,
      exp: expSec,
    };

    const accessToken = createMockJwt({
      ...idTokenClaims,
      scope: this.config.scope,
    });

    const idToken = createMockJwt(idTokenClaims);

    const user: UserProfile = {
      sub: persona.sub,
      name: persona.name,
      email: persona.email,
      preferred_username: persona.email.split('@')[0],
      roles: persona.roles,
      title: persona.title,
      idp: this.config.isMock ? 'Dev / Demo Mock IdP' : 'Enterprise IdP',
      sessionExpiresAt: Date.now() + 15 * 60 * 1000, // NFR-029: 15-minute idle limit
    };

    const tokens: OidcTokens = {
      accessToken,
      idToken,
      expiresIn: 3600,
      tokenType: 'Bearer',
      scope: this.config.scope,
    };

    this.saveSession(user, tokens);
    return { user, tokens };
  }

  /**
   * Starts RFC 7636 Authorization Code Flow with PKCE against the live OIDC IdP
   */
  async startAuthorizationRedirect(): Promise<void> {
    if (this.config.isMock) {
      // In mock mode, defaults to Elena
      this.createMockSession('elena');
      return;
    }

    const codeVerifier = generateRandomString(64);
    const codeChallenge = await computeSha256Challenge(codeVerifier);
    const state = generateRandomString(32);
    const nonce = generateRandomString(32);

    sessionStorage.setItem(STORAGE_PKCE_VERIFIER_KEY, codeVerifier);
    sessionStorage.setItem(STORAGE_STATE_KEY, state);
    sessionStorage.setItem(STORAGE_NONCE_KEY, nonce);

    const authEndpoint = `${this.config.authority.replace(/\/+$/, '')}/protocol/openid-connect/auth`;
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

    window.location.href = `${authEndpoint}?${params.toString()}`;
  }

  /**
   * Handles redirect callback with authorization code
   */
  async handleCallback(searchParams: URLSearchParams): Promise<{ user: UserProfile; tokens: OidcTokens } | null> {
    const code = searchParams.get('code');
    const returnedState = searchParams.get('state');

    if (!code) return null;

    if (this.config.isMock) {
      return this.createMockSession('elena');
    }

    const savedState = sessionStorage.getItem(STORAGE_STATE_KEY);
    const codeVerifier = sessionStorage.getItem(STORAGE_PKCE_VERIFIER_KEY);

    if (!savedState || returnedState !== savedState || !codeVerifier) {
      throw new Error('OIDC State mismatch or missing PKCE verifier (potential CSRF).');
    }

    // Exchange code for tokens at the token endpoint
    const tokenEndpoint = `${this.config.authority.replace(/\/+$/, '')}/protocol/openid-connect/token`;
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      code,
      code_verifier: codeVerifier,
    });

    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Failed to exchange authorization code for tokens: ${errText}`);
    }

    const data = await response.json();
    const idTokenClaims = parseJwtPayload(data.id_token || data.access_token);

    // Extract roles from realm_access or roles array
    let roles: UserRole[] = ['viewer'];
    const claimRoles = (idTokenClaims.roles as string[]) ||
      ((idTokenClaims.realm_access as { roles?: string[] })?.roles) || [];

    const validRoles: UserRole[] = ['admin', 'auditor', 'operator', 'viewer'];
    const mappedRoles = claimRoles
      .map((r: string) => r.toLowerCase() as UserRole)
      .filter((r: UserRole) => validRoles.includes(r));

    if (mappedRoles.length > 0) {
      roles = mappedRoles;
    }

    const user: UserProfile = {
      sub: String(idTokenClaims.sub || 'user-unknown'),
      name: String(idTokenClaims.name || idTokenClaims.preferred_username || 'Enterprise Operator'),
      email: String(idTokenClaims.email || 'operator@enterprise.internal'),
      preferred_username: idTokenClaims.preferred_username ? String(idTokenClaims.preferred_username) : undefined,
      roles,
      title: roles.includes('admin') ? 'SecOps Admin' : roles.includes('auditor') ? 'CISO / Auditor' : 'Platform Engineer',
      idp: this.config.authority,
      sessionExpiresAt: Date.now() + 15 * 60 * 1000,
    };

    const tokens: OidcTokens = {
      accessToken: data.access_token,
      idToken: data.id_token || data.access_token,
      refreshToken: data.refresh_token,
      expiresIn: data.expires_in || 3600,
      tokenType: data.token_type || 'Bearer',
      scope: data.scope || this.config.scope,
    };

    // Clean up temporary PKCE keys
    sessionStorage.removeItem(STORAGE_PKCE_VERIFIER_KEY);
    sessionStorage.removeItem(STORAGE_STATE_KEY);
    sessionStorage.removeItem(STORAGE_NONCE_KEY);

    this.saveSession(user, tokens);
    return { user, tokens };
  }

  saveSession(user: UserProfile, tokens: OidcTokens): void {
    try {
      sessionStorage.setItem(
        STORAGE_SESSION_KEY,
        JSON.stringify({
          user,
          tokens,
        })
      );
    } catch {
      // Storage unavailable
    }
  }

  getSavedSession(): { user: UserProfile; tokens: OidcTokens } | null {
    try {
      const raw = sessionStorage.getItem(STORAGE_SESSION_KEY);
      if (!raw) return null;
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  clearSession(): void {
    try {
      sessionStorage.removeItem(STORAGE_SESSION_KEY);
      sessionStorage.removeItem(STORAGE_PKCE_VERIFIER_KEY);
      sessionStorage.removeItem(STORAGE_STATE_KEY);
      sessionStorage.removeItem(STORAGE_NONCE_KEY);
    } catch {
      // Ignore
    }
  }
}

export const oidcService = new OidcService();
