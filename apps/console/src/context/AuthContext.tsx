/**
 * Specification Anchors: FEAT-009, NFR-029, screens.md, user-personas.md
 * React Auth Context providing OIDC session management, RBAC enforcement,
 * and 15-minute inactivity session tracking (NFR-029).
 */

import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { AuthContextType, OidcConfig, OidcTokens, UserProfile, UserRole } from '../types/auth';
import { oidcService, ENTERPRISE_PERSONAS } from '../services/oidc';

const IDLE_TIMEOUT_SECONDS = 15 * 60; // NFR-029: 15 minutes idle expiration

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const oidcConfig: OidcConfig = oidcService.getConfig();

  const [user, setUser] = useState<UserProfile | null>(null);
  const [tokens, setTokens] = useState<OidcTokens | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSessionExpired, setIsSessionExpired] = useState(false);
  const [idleRemainingSeconds, setIdleRemainingSeconds] = useState(IDLE_TIMEOUT_SECONDS);

  const lastActivityRef = useRef<number>(Date.now());
  const throttleActivityRef = useRef<number>(0);

  // Load initial session or handle OIDC callback
  useEffect(() => {
    const initAuth = async () => {
      try {
        const searchParams = new URLSearchParams(window.location.search);
        if (searchParams.has('code')) {
          const result = await oidcService.handleCallback(searchParams);
          if (result) {
            setUser(result.user);
            setTokens(result.tokens);
            // Clean code/state from URL address bar
            const cleanUrl = window.location.pathname + window.location.hash;
            window.history.replaceState({}, document.title, cleanUrl);
            setIsLoading(false);
            return;
          }
        }

        const saved = oidcService.getSavedSession();
        if (saved && saved.user) {
          setUser(saved.user);
          setTokens(saved.tokens);
        } else if (oidcConfig.isMock) {
          // In local development / open-core mock mode, auto-login as Elena Rostova for zero-friction
          const mock = oidcService.createMockSession('elena');
          setUser(mock.user);
          setTokens(mock.tokens);
        }
      } catch (err) {
        console.error('Authentication initialization failed:', err);
      } finally {
        setIsLoading(false);
      }
    };

    initAuth();
  }, [oidcConfig.isMock]);

  // Reset idle timer on user activity
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

  // Set up activity event listeners
  useEffect(() => {
    const events = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll'];
    events.forEach((evt) => window.addEventListener(evt, handleUserActivity, { passive: true }));

    return () => {
      events.forEach((evt) => window.removeEventListener(evt, handleUserActivity));
    };
  }, [handleUserActivity]);

  // NFR-029: 15-minute inactivity session expiration ticker
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

  const login = async (personaId?: string) => {
    setIsLoading(true);
    try {
      if (oidcConfig.isMock || personaId) {
        const mock = oidcService.createMockSession(personaId || 'elena');
        setUser(mock.user);
        setTokens(mock.tokens);
        setIsSessionExpired(false);
        lastActivityRef.current = Date.now();
        setIdleRemainingSeconds(IDLE_TIMEOUT_SECONDS);
      } else {
        await oidcService.startAuthorizationRedirect();
      }
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    oidcService.clearSession();
    setUser(null);
    setTokens(null);
    setIsSessionExpired(false);
  };

  const switchPersona = (personaId: string) => {
    if (ENTERPRISE_PERSONAS[personaId]) {
      const mock = oidcService.createMockSession(personaId);
      setUser(mock.user);
      setTokens(mock.tokens);
      setIsSessionExpired(false);
      lastActivityRef.current = Date.now();
      setIdleRemainingSeconds(IDLE_TIMEOUT_SECONDS);
    }
  };

  const renewSession = () => {
    lastActivityRef.current = Date.now();
    setIdleRemainingSeconds(IDLE_TIMEOUT_SECONDS);
    setIsSessionExpired(false);
    if (user) {
      const updatedUser = { ...user, sessionExpiresAt: Date.now() + IDLE_TIMEOUT_SECONDS * 1000 };
      setUser(updatedUser);
      if (tokens) {
        oidcService.saveSession(updatedUser, tokens);
      }
    }
  };

  const hasRole = (role: UserRole | UserRole[]): boolean => {
    if (!user) return false;
    const required = Array.isArray(role) ? role : [role];
    return user.roles.some((r) => required.includes(r));
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        tokens,
        isAuthenticated: !!user,
        isLoading,
        isSessionExpired,
        idleRemainingSeconds,
        login,
        logout,
        switchPersona,
        renewSession,
        hasRole,
        oidcConfig,
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
