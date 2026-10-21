/**
 * Specification Anchors: FEAT-009, NFR-029, screens.md, user-personas.md
 * OIDC and RBAC Identity definitions for AegisMCP Web Security Console
 */

export type UserRole = 'admin' | 'auditor' | 'operator' | 'viewer';

export interface UserProfile {
  sub: string;
  name: string;
  email: string;
  preferred_username?: string;
  roles: UserRole[];
  title: string;
  avatarUrl?: string;
  idp: string;
  sessionExpiresAt: number;
}

export interface OidcTokens {
  idToken: string;
  accessToken: string;
  refreshToken?: string;
  expiresIn: number;
  tokenType: string;
  scope: string;
}

export interface OidcConfig {
  authority: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  isMock: boolean;
}

export interface AuthContextType {
  user: UserProfile | null;
  tokens: OidcTokens | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  isSessionExpired: boolean;
  idleRemainingSeconds: number;
  login: (personaId?: string) => Promise<void>;
  logout: () => void;
  switchPersona: (personaId: string) => void;
  renewSession: () => void;
  hasRole: (role: UserRole | UserRole[]) => boolean;
  oidcConfig: OidcConfig;
}
