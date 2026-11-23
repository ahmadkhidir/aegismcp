/**
 * Specification Anchors: FEAT-009, NFR-029, screens.md, user-flow.md
 * OIDC identity, claim mapping, token verification, and the idle session lock.
 *
 * Test doubles for the provider live only in this test module.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, act, waitFor } from '@testing-library/react';
import { AuthProvider, useAuth } from '../context/AuthContext';
import { UserProfileMenu } from '../components/UserProfileMenu';
import { SessionTimeoutModal } from '../components/SessionTimeoutModal';
import { LoginScreen } from '../components/LoginScreen';
import {
  OidcError,
  OidcService,
  profileFromClaims,
  readOidcConfig,
  verifyIdToken,
} from '../services/oidc';
import { OidcConfig, OidcTokens, UserProfile } from '../types/auth';

const BASE_CONFIG: OidcConfig = {
  authority: 'https://idp.test/realms/aegis',
  clientId: 'aegis-console',
  redirectUri: 'http://localhost:3000/',
  scope: 'openid profile email roles',
  configurationErrors: [],
};

function base64Url(value: string): string {
  return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unsignedToken(payload: Record<string, unknown>): string {
  return `${base64Url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))}.${base64Url(
    JSON.stringify(payload)
  )}.test-signature`;
}

const TEST_USER: UserProfile = {
  sub: 'user-42',
  name: 'Ada Lovelace',
  email: 'ada@example.com',
  roles: ['admin', 'auditor'],
  idp: BASE_CONFIG.authority,
  sessionExpiresAt: Date.now() + 15 * 60 * 1000,
};

function savedSession(): { user: UserProfile; tokens: OidcTokens } {
  return {
    user: TEST_USER,
    tokens: {
      idToken: unsignedToken({ exp: Math.floor(Date.now() / 1000) + 3600 }),
      accessToken: 'test-access-token',
      expiresIn: 3600,
      tokenType: 'Bearer',
      scope: 'openid profile email roles',
    },
  };
}

function fakeService(
  saved: { user: UserProfile; tokens: OidcTokens } | null,
  config: OidcConfig = BASE_CONFIG
): OidcService {
  return {
    getConfig: () => config,
    isConfigured: config.configurationErrors.length === 0,
    getSavedSession: () => saved,
    getAccessToken: () => saved?.tokens.accessToken ?? null,
    isTokenFresh: () => true,
    saveSession: vi.fn(),
    clearSession: vi.fn(),
    handleCallback: vi.fn().mockResolvedValue(null),
    startAuthorizationRedirect: vi.fn().mockResolvedValue(undefined),
  } as unknown as OidcService;
}

const AuthConsumer: React.FC = () => {
  const {
    user,
    isAuthenticated,
    isSessionExpired,
    idleRemainingSeconds,
    hasRole,
    logout,
    renewSession,
    authError,
  } = useAuth();
  return (
    <div>
      <div data-testid="auth-status">{isAuthenticated ? 'AUTHENTICATED' : 'ANONYMOUS'}</div>
      <div data-testid="auth-user-name">{user?.name}</div>
      <div data-testid="auth-user-email">{user?.email}</div>
      <div data-testid="auth-is-admin">{hasRole('admin') ? 'YES_ADMIN' : 'NO_ADMIN'}</div>
      <div data-testid="auth-is-auditor">{hasRole('auditor') ? 'YES_AUDITOR' : 'NO_AUDITOR'}</div>
      <div data-testid="auth-session-expired">{isSessionExpired ? 'EXPIRED' : 'ACTIVE'}</div>
      <div data-testid="auth-idle-seconds">{idleRemainingSeconds}</div>
      <div data-testid="auth-error-code">{authError?.code ?? ''}</div>
      <button data-testid="btn-renew" onClick={() => renewSession()}>
        Renew
      </button>
      <button data-testid="btn-logout" onClick={() => logout()}>
        Logout
      </button>
    </div>
  );
};

beforeEach(() => {
  sessionStorage.clear();
  vi.clearAllMocks();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('Identity configuration', () => {
  it('names the missing settings instead of inventing one', () => {
    const config = readOidcConfig({} as ImportMetaEnv);
    expect(config.configurationErrors).toEqual([
      'VITE_OIDC_AUTHORITY',
      'VITE_OIDC_CLIENT_ID',
    ]);
    expect(config.authority).toBe('');
  });

  it('accepts an issuer and client ID from the environment', () => {
    const config = readOidcConfig({
      VITE_OIDC_AUTHORITY: 'https://idp.example.com/realms/aegis/',
      VITE_OIDC_CLIENT_ID: 'console',
    } as unknown as ImportMetaEnv);
    expect(config.configurationErrors).toEqual([]);
    expect(config.authority).toBe('https://idp.example.com/realms/aegis');
    expect(config.clientId).toBe('console');
  });
});

describe('Claim-derived profile', () => {
  it('reads roles from direct, realm, and resource-access claims', () => {
    const claims = {
      sub: 'user-1',
      name: 'Grace Hopper',
      email: 'grace@example.com',
      roles: ['ADMIN'],
      realm_access: { roles: ['auditor'] },
      resource_access: { 'aegis-console': { roles: ['operator', 'unknown'] } },
      iss: BASE_CONFIG.authority,
    };
    const profile = profileFromClaims(claims, BASE_CONFIG.clientId, BASE_CONFIG.authority);
    expect(profile.name).toBe('Grace Hopper');
    expect(profile.email).toBe('grace@example.com');
    expect(profile.roles).toEqual(['admin', 'auditor', 'operator']);
    expect(profile.idp).toBe(BASE_CONFIG.authority);
  });

  it('denies a verified user with no console role', () => {
    expect(() =>
      profileFromClaims(
        { sub: 'user-2', name: 'No Role', roles: [] },
        BASE_CONFIG.clientId,
        BASE_CONFIG.authority
      )
    ).toThrowError(OidcError);
  });
});

describe('ID token verification', () => {
  async function signToken(claims: Record<string, unknown>) {
    const keyPair = (await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify']
    )) as CryptoKeyPair;

    const publicJwk = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as JsonWebKey & {
      kid?: string;
      alg?: string;
      use?: string;
    };
    publicJwk.kid = 'test-key';
    publicJwk.alg = 'RS256';
    publicJwk.use = 'sig';

    const header = base64Url(JSON.stringify({ alg: 'RS256', kid: 'test-key', typ: 'JWT' }));
    const payload = base64Url(JSON.stringify(claims));
    const signature = await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      keyPair.privateKey,
      new TextEncoder().encode(`${header}.${payload}`)
    );

    return {
      token: `${header}.${payload}.${base64Url(String.fromCharCode(...new Uint8Array(signature)))}`,
      jwk: publicJwk,
    };
  }

  function stubJwks(jwk: JsonWebKey) {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        ok: true,
        status: 200,
        json: async () => ({ keys: [jwk] }),
      })) as unknown as typeof fetch
    );
  }

  it('accepts a valid signature, issuer, audience, lifetime, and nonce', async () => {
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      sub: 'user-1',
      iss: BASE_CONFIG.authority,
      aud: BASE_CONFIG.clientId,
      exp: now + 300,
      nonce: 'nonce-123',
    };
    const { token, jwk } = await signToken(claims);
    stubJwks(jwk);

    const verified = await verifyIdToken(token, {
      issuer: BASE_CONFIG.authority,
      clientId: BASE_CONFIG.clientId,
      jwksUri: `https://idp.test/jwks/${Math.random()}`,
      nonce: 'nonce-123',
    });
    expect(verified.sub).toBe('user-1');
  });

  it('rejects an expired token even when the signature is valid', async () => {
    const now = Math.floor(Date.now() / 1000);
    const { token, jwk } = await signToken({
      sub: 'user-1',
      iss: BASE_CONFIG.authority,
      aud: BASE_CONFIG.clientId,
      exp: now - 120,
    });
    stubJwks(jwk);

    await expect(
      verifyIdToken(token, {
        issuer: BASE_CONFIG.authority,
        clientId: BASE_CONFIG.clientId,
        jwksUri: `https://idp.test/jwks/${Math.random()}`,
      })
    ).rejects.toThrow(/expired/i);
  });

  it('rejects a token issued for another client', async () => {
    const now = Math.floor(Date.now() / 1000);
    const { token, jwk } = await signToken({
      sub: 'user-1',
      iss: BASE_CONFIG.authority,
      aud: 'another-client',
      exp: now + 300,
    });
    stubJwks(jwk);

    await expect(
      verifyIdToken(token, {
        issuer: BASE_CONFIG.authority,
        clientId: BASE_CONFIG.clientId,
        jwksUri: `https://idp.test/jwks/${Math.random()}`,
      })
    ).rejects.toThrow(/another client/i);
  });
});

describe('AuthProvider session lifecycle', () => {
  it('restores a verified session and exposes its roles', async () => {
    render(
      <AuthProvider service={fakeService(savedSession())}>
        <AuthConsumer />
      </AuthProvider>
    );

    expect(await screen.findByTestId('auth-status')).toHaveTextContent('AUTHENTICATED');
    expect(screen.getByTestId('auth-user-name')).toHaveTextContent('Ada Lovelace');
    expect(screen.getByTestId('auth-user-email')).toHaveTextContent('ada@example.com');
    expect(screen.getByTestId('auth-is-admin')).toHaveTextContent('YES_ADMIN');
    expect(screen.getByTestId('auth-is-auditor')).toHaveTextContent('YES_AUDITOR');
  });

  it('signs out to an anonymous session with no residual identity', async () => {
    const service = fakeService(savedSession());
    render(
      <AuthProvider service={service}>
        <AuthConsumer />
      </AuthProvider>
    );

    await screen.findByText('AUTHENTICATED');
    fireEvent.click(screen.getByTestId('btn-logout'));

    expect(screen.getByTestId('auth-status')).toHaveTextContent('ANONYMOUS');
    expect(screen.getByTestId('auth-user-name')).toHaveTextContent('');
    expect(service.clearSession).toHaveBeenCalled();
  });

  it('locks after 15 minutes of inactivity and resumes a still-valid token', async () => {
    vi.useFakeTimers();
    render(
      <AuthProvider service={fakeService(savedSession())}>
        <AuthConsumer />
      </AuthProvider>
    );

    expect(screen.getByTestId('auth-session-expired')).toHaveTextContent('ACTIVE');

    act(() => {
      vi.advanceTimersByTime(14 * 60 * 1000);
    });
    expect(screen.getByTestId('auth-session-expired')).toHaveTextContent('ACTIVE');

    act(() => {
      vi.advanceTimersByTime(61 * 1000);
    });
    expect(screen.getByTestId('auth-session-expired')).toHaveTextContent('EXPIRED');

    await act(async () => {
      fireEvent.click(screen.getByTestId('btn-renew'));
    });
    expect(screen.getByTestId('auth-session-expired')).toHaveTextContent('ACTIVE');
  });
});

describe('LoginScreen', () => {
  it('explains missing configuration and keeps sign-in disabled', async () => {
    const config: OidcConfig = {
      ...BASE_CONFIG,
      authority: '',
      clientId: '',
      configurationErrors: ['VITE_OIDC_AUTHORITY', 'VITE_OIDC_CLIENT_ID'],
    };

    render(
      <AuthProvider service={fakeService(null, config)}>
        <LoginScreen />
      </AuthProvider>
    );

    expect(await screen.findByTestId('login-configuration-error')).toBeInTheDocument();
    expect(screen.getByText('VITE_OIDC_AUTHORITY')).toBeInTheDocument();
    expect(screen.getByTestId('sso-primary-login-button')).toBeDisabled();
  });

  it('starts the configured provider flow instead of choosing a local identity', async () => {
    const service = fakeService(null);
    render(
      <AuthProvider service={service}>
        <LoginScreen />
      </AuthProvider>
    );

    const button = await screen.findByTestId('sso-primary-login-button');
    await waitFor(() => expect(button).not.toBeDisabled());
    await act(async () => {
      fireEvent.click(button);
    });

    expect(service.startAuthorizationRedirect).toHaveBeenCalledTimes(1);
  });
});

describe('UserProfileMenu', () => {
  it('shows the verified identity and directory roles without a persona switcher', async () => {
    render(
      <AuthProvider service={fakeService(savedSession())}>
        <UserProfileMenu />
      </AuthProvider>
    );

    const menuButton = await screen.findByTestId('user-profile-menu-button');
    expect(screen.getByText('Ada Lovelace')).toBeInTheDocument();

    fireEvent.click(menuButton);

    expect(screen.getByTestId('user-profile-dropdown')).toBeInTheDocument();
    expect(screen.getByText('Directory roles')).toBeInTheDocument();
    expect(screen.getByText('admin')).toBeInTheDocument();
    expect(screen.getByTestId('idle-timer-display')).toBeInTheDocument();
    expect(screen.queryByText(/switch persona/i)).not.toBeInTheDocument();
  });
});

describe('SessionTimeoutModal', () => {
  it('renders the inactivity lock and handles renew and sign-out', () => {
    const onRenew = vi.fn();
    const onLogout = vi.fn();

    const { rerender } = render(
      <SessionTimeoutModal
        isOpen={false}
        userName="Ada Lovelace"
        onRenew={onRenew}
        onLogout={onLogout}
      />
    );
    expect(screen.queryByText(/Session locked/i)).not.toBeInTheDocument();

    rerender(
      <SessionTimeoutModal
        isOpen={true}
        userName="Ada Lovelace"
        onRenew={onRenew}
        onLogout={onLogout}
      />
    );

    expect(screen.getByText(/Session locked/i)).toBeInTheDocument();
    expect(screen.getByText('Ada Lovelace')).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('timeout-renew-button'));
    expect(onRenew).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByTestId('timeout-logout-button'));
    expect(onLogout).toHaveBeenCalledTimes(1);
  });
});
