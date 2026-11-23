/**
 * Specification Anchors: FEAT-009, NFR-029, screens.md § Navigation Map
 * Enterprise SSO sign-in gate. The screen starts the configured provider's
 * PKCE flow; it never offers a local identity shortcut or creates a session.
 */

import React from 'react';
import { AlertCircle, ArrowRight, KeyRound, Loader2, Shield, UserCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const LoginScreen: React.FC = () => {
  const { authError, configurationErrors, isLoading, isAuthenticating, login } = useAuth();
  const isConfigured = configurationErrors.length === 0;
  const isAccessDenied = authError?.code === 'ACCESS_DENIED';

  return (
    <div className="min-h-screen bg-grey-50 flex flex-col justify-center items-center p-space-md font-sans text-grey-900">
      <div className="w-full max-w-lg bg-grey-100 border border-grey-300 rounded-radius-lg shadow-xl p-space-xl">
        <div className="flex flex-col items-center text-center mb-space-xl">
          <div className="w-12 h-12 flex items-center justify-center rounded-radius-md bg-grey-50 border border-grey-300 shadow-sm mb-space-sm">
            <svg className="w-8 h-8" viewBox="0 0 32 32" fill="none" aria-hidden="true">
              <path
                d="M16 2L28 9V23L16 30L4 23V9L16 2Z"
                className="stroke-primary-500 fill-grey-50"
                strokeWidth="2"
              />
              <path
                d="M16 7L23 11V21L16 25L9 21V11L16 7Z"
                className="stroke-primary-300 fill-grey-200"
                strokeWidth="1.5"
              />
              <circle cx="16" cy="16" r="3" className="fill-primary-500" />
            </svg>
          </div>
          <div className="flex items-center gap-1.5 mb-1">
            <h1 className="font-bold text-h1 tracking-tight text-grey-900">Aegis</h1>
            <span className="font-mono text-body-small font-semibold px-2 py-0.5 rounded-radius-sm bg-grey-200 text-primary-800 border border-grey-300">
              MCP
            </span>
          </div>
          <p className="text-caption text-grey-500 font-medium">
            Zero-Trust Reverse Proxy & Security Firewall for Model Context Protocol
          </p>
        </div>

        {!isConfigured && (
          <div
            role="alert"
            data-testid="login-configuration-error"
            className="mb-space-md p-space-md rounded-radius-md bg-warning-100 border border-warning-300 text-warning-900 text-caption space-y-1.5"
          >
            <div className="flex items-center gap-1.5 font-semibold">
              <AlertCircle className="w-4 h-4 text-warning-500" />
              <span>Sign-in is not configured for this deployment.</span>
            </div>
            <p className="text-warning-700">
              Set the following settings in the console environment, rebuild, and reload:
            </p>
            <ul className="list-disc list-inside font-mono">
              {configurationErrors.map((setting) => (
                <li key={setting}>{setting}</li>
              ))}
            </ul>
            <p className="text-warning-700">
              The console cannot create a session until an identity provider is configured.
            </p>
          </div>
        )}

        {authError && (
          <div
            role="alert"
            data-testid="login-auth-error"
            className={`mb-space-md p-space-md rounded-radius-md border text-caption space-y-1.5 ${
              isAccessDenied
                ? 'bg-warning-100 border-warning-300 text-warning-900'
                : 'bg-error-100 border-error-300 text-error-900'
            }`}
          >
            <div className="flex items-center gap-1.5 font-semibold">
              <AlertCircle
                className={`w-4 h-4 ${isAccessDenied ? 'text-warning-500' : 'text-error-500'}`}
              />
              <span>{isAccessDenied ? 'Access denied' : 'Sign-in failed'}</span>
            </div>
            <p>{authError.message}</p>
            {!isAccessDenied && isConfigured && (
              <button
                type="button"
                onClick={() => login()}
                className="font-semibold underline underline-offset-2"
              >
                Try signing in again
              </button>
            )}
          </div>
        )}

        <div className="space-y-space-md mb-space-lg">
          <div className="p-space-md rounded-radius-md bg-grey-200 border border-grey-300 text-left">
            <div className="flex items-center gap-2 text-caption font-semibold text-grey-700 mb-1">
              <KeyRound className="w-4 h-4 text-primary-500" />
              <span>Enterprise Single Sign-On (OIDC / SAML)</span>
            </div>
            <p className="text-caption text-grey-500 mb-space-md">
              {isConfigured
                ? 'Your organization signs you in with multi-factor authentication. Console roles come from your directory groups.'
                : 'An identity provider must be configured before console sign-in can start.'}
            </p>

            <button
              onClick={() => login()}
              disabled={isLoading || isAuthenticating || !isConfigured}
              data-testid="sso-primary-login-button"
              className="w-full py-2.5 px-space-md rounded-radius-md bg-primary-600 hover:bg-primary-500 text-grey-900 font-bold text-caption shadow-sm transition-all flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isAuthenticating ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Shield className="w-4 h-4" />
              )}
              <span>
                {isAuthenticating
                  ? 'Redirecting to your identity provider…'
                  : 'Sign in with Enterprise SSO'}
              </span>
              {!isAuthenticating && <ArrowRight className="w-4 h-4" />}
            </button>
          </div>
        </div>

        <div className="mt-space-lg pt-space-md border-t border-grey-300 text-center">
          <p className="text-caption text-grey-500 font-mono flex items-center justify-center gap-1">
            <UserCheck className="w-3 h-3 text-success-500" />
            <span>Multi-factor sign-in · role-based access · automatic idle lock</span>
          </p>
        </div>
      </div>
    </div>
  );
};
