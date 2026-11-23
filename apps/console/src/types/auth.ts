/**
 * Specification Anchors: FEAT-009, NFR-029, screens.md, user-flow.md
 * Identity, session, and role shapes for the web console.
 *
 * The profile is built only from claims of an ID token the console has verified
 * against the configured provider. There is no local identity catalogue.
 */

export type UserRole = 'admin' | 'auditor' | 'operator' | 'viewer';

export interface UserProfile {
  sub: string;
  name: string;
  email: string;
  preferredUsername?: string;
  roles: UserRole[];
  idp: string;
  sessionExpiresAt: number;
}

export interface OidcTokens {
  idToken: string;
  accessToken: string;
  refreshToken?: string;
  /** Seconds from issue until the access token expires. */
  expiresIn: number;
  tokenType: string;
  scope: string;
}

export interface OidcConfig {
  authority: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  /** Required environment settings that are absent, named for the operator. */
  configurationErrors: string[];
}

export type AuthErrorCode =
  | 'CONFIGURATION'
  | 'DISCOVERY'
  | 'CALLBACK'
  | 'TOKEN_EXCHANGE'
  | 'TOKEN_VERIFICATION'
  | 'ACCESS_DENIED';

export interface AuthErrorInfo {
  code: AuthErrorCode;
  message: string;
}

export interface AuthContextType {
  user: UserProfile | null;
  tokens: OidcTokens | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  isAuthenticating: boolean;
  isSessionExpired: boolean;
  idleRemainingSeconds: number;
  authError: AuthErrorInfo | null;
  configurationErrors: string[];
  login: () => Promise<void>;
  logout: () => void;
  renewSession: () => Promise<void>;
  hasRole: (role: UserRole | UserRole[]) => boolean;
}
