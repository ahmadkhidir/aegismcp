import React from 'react';
import { Shield, ChevronDown, User, Server, Menu } from 'lucide-react';
import { ThreatLevel } from '../types/contracts';

interface NavbarProps {
  threatLevel: ThreatLevel;
  onOpenKillSwitch: () => void;
  onToggleMobileMenu?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ threatLevel, onOpenKillSwitch, onToggleMobileMenu }) => {
  return (
    <header className="h-14 border-b border-grey-300 bg-grey-100 px-space-md sm:px-space-lg flex items-center justify-between sticky top-0 z-40">
      {/* Brand logo & mobile menu toggle */}
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
          <svg className="w-5 h-5 text-primary-500" viewBox="0 0 32 32" fill="none">
            <path d="M16 2L28 9V23L16 30L4 23V9L16 2Z" stroke="currentColor" strokeWidth="2" fill="#0B0F19"/>
            <path d="M16 7L23 11V21L16 25L9 21V11L16 7Z" stroke="#93C5FD" strokeWidth="1.5" fill="#1E293B"/>
            <circle cx="16" cy="16" r="3" fill="currentColor"/>
          </svg>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="font-bold text-lg tracking-tight text-grey-900 font-sans">Aegis</span>
          <span className="font-mono text-xs font-semibold px-1.5 py-0.5 rounded-radius-sm bg-grey-200 text-primary-800 border border-grey-300">
            MCP
          </span>
        </div>
      </div>

      {/* Cluster selection & Environment badge */}
      <div className="hidden md:flex items-center gap-space-md">
        <div className="flex items-center gap-1.5 px-space-sm py-1 rounded-radius-md bg-grey-200 border border-grey-300 text-xs text-grey-700">
          <Server className="w-3.5 h-3.5 text-primary-500" />
          <span className="font-mono font-medium">prod-eu-central-1</span>
          <ChevronDown className="w-3.5 h-3.5 text-grey-500" />
        </div>
        <span className="px-2 py-0.5 rounded-radius-full text-[11px] font-mono font-bold bg-primary-100 text-primary-800 border border-primary-300">
          PRODUCTION
        </span>
      </div>

      {/* Threat posture trigger & User profile */}
      <div className="flex items-center gap-space-md">
        <button
          onClick={onOpenKillSwitch}
          data-testid="nav-killswitch-button"
          className={`px-space-md py-1.5 rounded-radius-md text-xs font-bold transition-all shadow-sm flex items-center gap-1.5 ${
            threatLevel === 'LOCKDOWN'
              ? 'bg-error-500 text-grey-900 animate-pulse'
              : 'bg-grey-200 hover:bg-error-500/20 text-error-700 hover:text-error-900 border border-error-300'
          }`}
        >
          <Shield className="w-3.5 h-3.5" />
          <span>{threatLevel === 'LOCKDOWN' ? 'SYSTEM IN LOCKDOWN' : 'Kill-Switch'}</span>
        </button>

        <div className="flex items-center gap-2 pl-space-sm border-l border-grey-300">
          <div className="w-7 h-7 rounded-radius-full bg-primary-200 flex items-center justify-center text-primary-900 font-semibold text-xs border border-primary-400">
            <User className="w-3.5 h-3.5" />
          </div>
          <div className="hidden lg:block text-left">
            <p className="text-xs font-medium text-grey-900 leading-none">Elena Rostova</p>
            <p className="text-[10px] text-grey-500 font-mono leading-tight">SecOps Admin</p>
          </div>
        </div>
      </div>
    </header>
  );
};
