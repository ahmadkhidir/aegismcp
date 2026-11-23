/**
 * Specification Anchors: FEAT-009, NFR-029, screens.md, user-flow.md
 * Session context: restores a verified session, tracks the 15-minute idle
 * window, and exposes role checks to the shell.
 *
 * The context holds no fallback identity. When the provider is not configured
 * or the callback fails, the login screen explains the failure and no session
 * is created.
 */

import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import {
  AuthContextType,
  AuthErrorInfo,
  OidcTokens,
  UserProfile,
  UserRole,
} from '../types/auth';
import { OidcError, OidcService, oidcService } from '../services/oidc';

const IDLE_TIMEOUT_SECONDS = 15 * 60; // NFR-029: 15 minutes idle expiration

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: React.ReactNode;
  /** Injectable for tests; production uses the configured singleton. */
  service?: OidcService;
}

function toAuthError(error: unknown): AuthErrorInfo {
  if (error instanceof OidcError) {
    return { code: error.code, message: error.message };
  }
  if (error instanceof Error) {
    return { code: 'CALLBACK', message: error.message };
  }
  return { code: 'CALLBACK', message: 'Sign-in could not be completed.' };
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children, service = oidcService }) => {
  const config = service.getConfig();

  const [user, setUser] = useState<UserProfile | null>(null);
  const [tokens, setTokens] = useState<OidcTokens | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [isSessionExpired, setIsSessionExpired] = useState(false);
  const [idleRemainingSeconds, setIdleRemainingSeconds] = useState(IDLE_TIMEOUT_SECONDS);
  const [authError, setAuthError] = useState<AuthErrorInfo | null>(null);

  const lastActivityRef = useRef<number>(Date.now());
  const throttleActivityRef = useRef<number>(0);

  // Restore a verified session or complete the provider callback.
  useEffect(() => {
    let cancelled = false;

    const initAuth = async () => {
      try {
        if (!service.isConfigured) {
          service.clearSession();
          setUser(null);
          setTokens(null);
          return;
        }

        const searchParams = new URLSearchParams(window.location.search);
        if (searchParams.has('code') || searchParams.has('error')) {
          const providerError = searchParams.get('error_description') || searchParams.get('error');
          if (providerError) {
            throw new OidcError('CALLBACK', `The identity provider refused sign-in: ${providerError}`);
          }
          const result = await service.handleCallback(searchParams);
          if (cancelled) return;
          if (result) {
            setUser(result.user);
            setTokens(result.tokens);
            const cleanUrl = window.location.pathname + window.location.hash;
            window.history.replaceState({}, document.title, cleanUrl);
            return;
          }
        }

        const saved = service.getSavedSession();
        if (cancelled) return;
        if (saved) {
          setUser(saved.user);
          setTokens(saved.tokens);
          lastActivityRef.current = Date.now();
          setIdleRemainingSeconds(IDLE_TIMEOUT_SECONDS);
        }
      } catch (error) {
        if (cancelled) return;
        service.clearSession();
        setUser(null);
        setTokens(null);
        setAuthError(toAuthError(error));
        if (window.location.search) {
          window.history.replaceState({}, document.title, window.location.pathname + window.location.hash);
        }
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    };

    initAuth();
    return () => {
      cancelled = true;
    };
  }, [service]);

  // Reset the idle clock on genuine operator activity.
  const handleUserActivity = useCallback(() => {
    const now = Date.now();
    if (now - throttleActivityRef.current > 2000) {
      throttleActivityRef.current = now;
      if (!isSessionExpired) {
        lastActivityRef.current = now;
        setIdleRemainingSeconds(IDLE_TIMEOUT_SECONDS);
      }
    }
  }, [isSessionExpired]);

  useEffect(() => {
    const events = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll'];
    events.forEach((event) => window.addEventListener(event, handleUserActivity, { passive: true }));
    return () => {
      events.forEach((event) => window.removeEventListener(event, handleUserActivity));
    };
  }, [handleUserActivity]);

  // NFR-029: expire the local session after 15 minutes without activity.
  useEffect(() => {
    if (!user || isSessionExpired) return;
    const interval = setInterval(() => {
      const elapsed = Math.floor((Date.now() - lastActivityRef.current) / 1000);
      const remaining = Math.max(0, IDLE_TIMEOUT_SECONDS - elapsed);
      setIdleRemainingSeconds(remaining);
      if (remaining <= 0) {
        setIsSessionExpired(true);
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [user, isSessionExpired]);

  const login = async () => {
    setAuthError(null);
    if (!service.isConfigured) {
      setAuthError({
        code: 'CONFIGURATION',
        message: `Console sign-in is not configured. Missing: ${config.configurationErrors.join(', ')}.`,
      });
      return;
    }
    setIsAuthenticating(true);
    try {
      await service.startAuthorizationRedirect();
    } catch (error) {
      setIsAuthenticating(false);
      setAuthError(toAuthError(error));
    }
  };

  const logout = () => {
    service.clearSession();
    setUser(null);
    setTokens(null);
    setIsSessionExpired(false);
    setAuthError(null);
    lastActivityRef.current = Date.now();
    setIdleRemainingSeconds(IDLE_TIMEOUT_SECONDS);
  };

  /**
   * Resumes after the idle lock only while the provider-issued ID token is
   * still valid. Otherwise the operator is sent back through the provider.
   */
  const renewSession = async () => {
    if (tokens && service.isTokenFresh(tokens.idToken)) {
      lastActivityRef.current = Date.now();
      setIdleRemainingSeconds(IDLE_TIMEOUT_SECONDS);
      setIsSessionExpired(false);
      if (user) {
        const updatedUser = { ...user, sessionExpiresAt: Date.now() + IDLE_TIMEOUT_SECONDS * 1000 };
        setUser(updatedUser);
        service.saveSession(updatedUser, tokens);
      }
      return;
    }

    logout();
    await login();
  };

  const hasRole = (role: UserRole | UserRole[]): boolean => {
    if (!user) return false;
    const required = Array.isArray(role) ? role : [role];
    return user.roles.some((held) => required.includes(held));
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        tokens,
        isAuthenticated: !!user,
        isLoading,
        isAuthenticating,
        isSessionExpired,
        idleRemainingSeconds,
        authError,
        configurationErrors: config.configurationErrors,
        login,
        logout,
        renewSession,
        hasRole,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
