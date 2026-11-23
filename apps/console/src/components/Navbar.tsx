/**
 * Specification Anchors: FEAT-008, FEAT-010
 * Top navigation bar: brand, current threat posture, kill-switch entry, and
 * the signed-in operator menu.
 */

import React from 'react';
import { Shield, Menu } from 'lucide-react';
import { ThreatLevel } from '../types/contracts';
import { UserProfileMenu } from './UserProfileMenu';
import { useAuth } from '../context/AuthContext';

interface NavbarProps {
  threatLevel: ThreatLevel | null;
  onOpenKillSwitch: () => void;
  onToggleMobileMenu?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ threatLevel, onOpenKillSwitch, onToggleMobileMenu }) => {
  const { hasRole } = useAuth();
  const canTriggerKillSwitch = hasRole(['admin', 'operator']);

  return (
    <header className="h-14 border-b border-grey-300 bg-grey-100 px-space-md sm:px-space-lg flex items-center justify-between sticky top-0 z-40">
      <div className="flex items-center gap-2 sm:gap-3">
        {onToggleMobileMenu && (
          <button
            onClick={onToggleMobileMenu}
            data-testid="nav-mobile-toggle"
            className="lg:hidden p-1.5 rounded-radius-md text-grey-600 hover:text-grey-900 hover:bg-grey-200 transition-colors"
            aria-label="Toggle navigation menu"
          >
            <Menu className="w-5 h-5" />
          </button>
        )}
        <div className="w-8 h-8 flex items-center justify-center rounded-radius-md bg-grey-50 border border-grey-300 shadow-sm flex-shrink-0">
          <svg className="w-5 h-5" viewBox="0 0 32 32" fill="none" aria-hidden="true">
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
        <div className="flex items-center gap-1.5">
          <span className="font-bold text-h3 tracking-tight text-grey-900 font-sans">Aegis</span>
          <span className="font-mono text-caption font-semibold px-1.5 py-0.5 rounded-radius-sm bg-grey-200 text-primary-800 border border-grey-300">
            MCP
          </span>
        </div>
      </div>

      <div className="flex items-center gap-space-md">
        <button
          onClick={onOpenKillSwitch}
          disabled={!canTriggerKillSwitch}
          data-testid="nav-killswitch-button"
          title={
            canTriggerKillSwitch
              ? 'Open the emergency kill-switch'
              : 'The operator or admin role is required to use the kill-switch'
          }
          className={`px-space-md py-1.5 rounded-radius-md text-caption font-bold transition-all shadow-sm flex items-center gap-1.5 ${
            !canTriggerKillSwitch
              ? 'opacity-40 cursor-not-allowed bg-grey-200 text-grey-500 border border-grey-300'
              : threatLevel === 'LOCKDOWN'
              ? 'bg-error-500 text-grey-900 animate-pulse'
              : 'bg-grey-200 hover:bg-error-500/20 text-error-700 hover:text-error-900 border border-error-300'
          }`}
        >
          <Shield className="w-3.5 h-3.5" />
          <span>{threatLevel === 'LOCKDOWN' ? 'SYSTEM IN LOCKDOWN' : 'Kill-Switch'}</span>
        </button>

        <UserProfileMenu />
      </div>
    </header>
  );
};
