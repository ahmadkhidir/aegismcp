/**
 * Specification Anchors: FEAT-009, NFR-029, screens.md § Navigation Map
 * Enterprise SSO / OIDC Login Screen.
 * Renders when unauthenticated, redirecting to corporate IdP via PKCE or allowing
 * direct demo/dev persona selection.
 */

import React from 'react';
import { Shield, KeyRound, ArrowRight, UserCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { ENTERPRISE_PERSONAS } from '../services/oidc';

export const LoginScreen: React.FC = () => {
  const { login, oidcConfig, isLoading } = useAuth();

  return (
    <div className="min-h-screen bg-grey-50 flex flex-col justify-center items-center p-space-md font-sans text-grey-900">
      <div className="w-full max-w-lg bg-grey-100 border border-grey-300 rounded-radius-lg shadow-xl p-space-xl">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center mb-space-xl">
          <div className="w-12 h-12 flex items-center justify-center rounded-radius-md bg-grey-50 border border-grey-300 shadow-sm mb-space-sm">
            <svg className="w-8 h-8 text-primary-500" viewBox="0 0 32 32" fill="none">
              <path d="M16 2L28 9V23L16 30L4 23V9L16 2Z" stroke="currentColor" strokeWidth="2" fill="#0B0F19" />
              <path d="M16 7L23 11V21L16 25L9 21V11L16 7Z" stroke="#93C5FD" strokeWidth="1.5" fill="#1E293B" />
              <circle cx="16" cy="16" r="3" fill="currentColor" />
            </svg>
          </div>
          <div className="flex items-center gap-1.5 mb-1">
            <h1 className="font-bold text-2xl tracking-tight text-grey-900">Aegis</h1>
            <span className="font-mono text-sm font-semibold px-2 py-0.5 rounded-radius-sm bg-grey-200 text-primary-800 border border-grey-300">
              MCP
            </span>
          </div>
          <p className="text-xs text-grey-500 font-medium">
            Zero-Trust Reverse Proxy & Security Firewall for Model Context Protocol
          </p>
        </div>

        {/* Primary Enterprise SSO Action */}
        <div className="space-y-space-md mb-space-lg">
          <div className="p-space-md rounded-radius-md bg-grey-200 border border-grey-300 text-left">
            <div className="flex items-center gap-2 text-xs font-semibold text-grey-700 mb-1">
              <KeyRound className="w-4 h-4 text-primary-500" />
              <span>Enterprise Single Sign-On (OIDC / SAML)</span>
            </div>
            <p className="text-xs text-grey-500 mb-space-md">
              {oidcConfig.isMock
                ? 'Local / Dev Mode active. Live OIDC authority not set; use mock IdP or choose an enterprise persona below.'
                : `Authenticating with configured IdP: ${oidcConfig.authority}`}
            </p>

            <button
              onClick={() => login('elena')}
              disabled={isLoading}
              data-testid="sso-primary-login-button"
              className="w-full py-2.5 px-space-md rounded-radius-md bg-primary-600 hover:bg-primary-500 text-grey-900 font-bold text-xs shadow-sm transition-all flex items-center justify-center gap-2 disabled:opacity-50"
            >
              <Shield className="w-4 h-4" />
              <span>
                {oidcConfig.isMock
                  ? 'Sign In with Enterprise SSO (Elena Rostova / Admin)'
                  : 'Authenticate via Corporate IdP (PKCE)'}
              </span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Persona Selectors for Dev & Testing */}
        {oidcConfig.isMock && (
          <div>
            <div className="flex items-center justify-between mb-space-sm">
              <span className="text-[11px] font-semibold text-grey-500 uppercase tracking-wider">
                Select Persona (Dev / Staging)
              </span>
              <span className="text-[10px] text-primary-800 font-mono">docs/AegisMCP/user-personas.md</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-space-sm">
              {Object.entries(ENTERPRISE_PERSONAS).map(([key, persona]) => (
                <button
                  key={key}
                  onClick={() => login(key)}
                  data-testid={`login-as-${key}`}
                  className="flex items-start gap-2 p-space-sm rounded-radius-md bg-grey-200 hover:bg-grey-300 border border-grey-300 text-left transition-colors group"
                >
                  <div className="w-7 h-7 rounded-radius-full bg-primary-200 border border-primary-400 flex items-center justify-center text-primary-900 font-bold text-xs flex-shrink-0 group-hover:scale-105 transition-transform">
                    {persona.name.charAt(0)}
                  </div>
                  <div className="overflow-hidden">
                    <p className="text-xs font-bold text-grey-900 truncate">{persona.name}</p>
                    <p className="text-[10px] text-grey-500 truncate font-mono">{persona.title}</p>
                    <div className="flex gap-1 mt-1">
                      {persona.roles.map((r) => (
                        <span
                          key={r}
                          className="px-1 py-0.2 rounded-radius-sm text-[9px] font-mono uppercase bg-grey-300 text-grey-700"
                        >
                          {r}
                        </span>
                      ))}
                    </div>
                  </div>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="mt-space-lg pt-space-md border-t border-grey-300 text-center">
          <p className="text-[10px] text-grey-500 font-mono flex items-center justify-center gap-1">
            <UserCheck className="w-3 h-3 text-success-500" />
            <span>NFR-029 & FEAT-009 Zero-Trust Identity Compliant</span>
          </p>
        </div>
      </div>
    </div>
  );
};
