/**
 * Specification Anchors: FEAT-009, NFR-029, screens.md, user-personas.md
 * User Profile Dropdown Menu in Top Navigation.
 * Displays active operator identity, OIDC claims, RBAC roles, live NFR-029 idle timer,
 * and dev/demo persona switching.
 */

import React, { useState, useRef, useEffect } from 'react';
import { User, LogOut, Clock, Shield, RefreshCw, ChevronDown, Check } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { ENTERPRISE_PERSONAS } from '../services/oidc';

export const UserProfileMenu: React.FC = () => {
  const { user, logout, switchPersona, renewSession, idleRemainingSeconds, oidcConfig } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  // Close when clicking outside or pressing Escape
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('keydown', handleKeyDown);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen]);

  if (!user) return null;

  const formatIdleTime = (totalSeconds: number) => {
    const mins = Math.floor(totalSeconds / 60);
    const secs = totalSeconds % 60;
    return `${mins}m ${secs < 10 ? '0' : ''}${secs}s`;
  };

  const getRoleColor = (role: string) => {
    switch (role) {
      case 'admin':
        return 'bg-error-100 text-error-700 border-error-300';
      case 'auditor':
        return 'bg-accent-100 text-accent-700 border-accent-300';
      case 'operator':
        return 'bg-primary-100 text-primary-800 border-primary-300';
      default:
        return 'bg-grey-200 text-grey-600 border-grey-300';
    }
  };

  return (
    <div className="relative" ref={menuRef}>
      <button
        onClick={() => setIsOpen((prev) => !prev)}
        data-testid="user-profile-menu-button"
        aria-expanded={isOpen}
        aria-haspopup="true"
        aria-label="User profile and session options"
        className="flex items-center gap-2 pl-space-sm border-l border-grey-300 hover:opacity-90 transition-opacity focus:outline-none"
      >
        <div className="w-7 h-7 rounded-radius-full bg-primary-200 flex items-center justify-center text-primary-900 font-semibold text-xs border border-primary-400 flex-shrink-0">
          <User className="w-3.5 h-3.5" />
        </div>
        <div className="hidden lg:block text-left">
          <p className="text-xs font-medium text-grey-900 leading-none">{user.name}</p>
          <p className="text-[10px] text-grey-500 font-mono leading-tight">{user.title}</p>
        </div>
        <ChevronDown className="w-3.5 h-3.5 text-grey-500" />
      </button>

      {isOpen && (
        <div
          data-testid="user-profile-dropdown"
          className="absolute right-0 mt-2 w-72 rounded-radius-lg bg-grey-100 border border-grey-300 shadow-xl z-50 p-space-md text-grey-900 animate-fade-in font-sans"
        >
          {/* User Details */}
          <div className="flex items-start gap- space-sm pb-space-sm border-b border-grey-300">
            <div className="w-9 h-9 rounded-radius-full bg-primary-200 flex items-center justify-center text-primary-900 font-bold text-sm border border-primary-400 flex-shrink-0">
              {user.name.charAt(0)}
            </div>
            <div className="overflow-hidden flex-1">
              <p className="text-sm font-bold text-grey-900 truncate">{user.name}</p>
              <p className="text-xs text-grey-500 truncate font-mono">{user.email}</p>
              <p className="text-[10px] text-primary-800 font-mono mt-0.5 truncate">{user.idp}</p>
            </div>
          </div>

          {/* Assigned RBAC Roles */}
          <div className="py-space-sm border-b border-grey-300">
            <div className="flex items-center gap-1 text-[11px] font-semibold text-grey-500 mb-1">
              <Shield className="w-3 h-3 text-primary-500" />
              <span>RBAC Roles</span>
            </div>
            <div className="flex flex-wrap gap-1">
              {user.roles.map((role) => (
                <span
                  key={role}
                  className={`px-1.5 py-0.5 rounded-radius-sm text-[10px] font-mono font-bold uppercase border ${getRoleColor(
                    role
                  )}`}
                >
                  {role}
                </span>
              ))}
            </div>
          </div>

          {/* Idle Session Countdown (NFR-029) */}
          <div className="py-space-sm border-b border-grey-300 flex items-center justify-between text-xs">
            <div className="flex items-center gap-1.5 text-grey-500">
              <Clock className="w-3.5 h-3.5 text-warning-500" />
              <span>Idle timeout:</span>
            </div>
            <div className="flex items-center gap-1">
              <span
                data-testid="idle-timer-display"
                className={`font-mono text-xs font-bold ${
                  idleRemainingSeconds < 180 ? 'text-error-500 animate-pulse' : 'text-grey-700'
                }`}
              >
                {formatIdleTime(idleRemainingSeconds)}
              </span>
              <button
                onClick={() => renewSession()}
                title="Reset idle timer (NFR-029)"
                data-testid="renew-idle-timer-button"
                className="p-1 rounded-radius-sm hover:bg-grey-200 text-grey-500 hover:text-grey-900 transition-colors"
                aria-label="Reset session idle timer"
              >
                <RefreshCw className="w-3 h-3" />
              </button>
            </div>
          </div>

          {/* Persona Switcher (when in mock/dev mode) */}
          {oidcConfig.isMock && (
            <div className="py-space-sm border-b border-grey-300">
              <p className="text-[11px] font-semibold text-grey-500 mb-1.5">
                Switch Persona (Dev / Demo Mode)
              </p>
              <div className="space-y-1">
                {Object.entries(ENTERPRISE_PERSONAS).map(([key, p]) => {
                  const isSelected = user.email === p.email;
                  return (
                    <button
                      key={key}
                      onClick={() => {
                        switchPersona(key);
                        setIsOpen(false);
                      }}
                      data-testid={`switch-persona-${key}`}
                      className={`w-full flex items-center justify-between px-2 py-1.5 rounded-radius-md text-xs text-left transition-colors ${
                        isSelected
                          ? 'bg-primary-100 text-primary-900 font-bold border border-primary-300'
                          : 'hover:bg-grey-200 text-grey-700'
                      }`}
                    >
                      <div className="truncate">
                        <span className="block truncate">{p.name}</span>
                        <span className="text-[10px] text-grey-500 block truncate font-mono">
                          {p.title}
                        </span>
                      </div>
                      {isSelected && <Check className="w-3.5 h-3.5 text-primary-600 flex-shrink-0" />}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Logout Action */}
          <div className="pt-space-sm">
            <button
              onClick={() => {
                logout();
                setIsOpen(false);
              }}
              data-testid="logout-button"
              className="w-full flex items-center gap-2 px-2 py-1.5 rounded-radius-md text-xs font-semibold text-error-500 hover:bg-error-500/10 hover:text-error-700 transition-colors"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Sign Out</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
