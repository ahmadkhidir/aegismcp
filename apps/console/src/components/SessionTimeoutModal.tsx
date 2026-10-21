/**
 * Specification Anchors: NFR-029, user-flow.md § Authentication Gate
 * Inactivity Re-authentication Modal displayed after 15 minutes of idle time.
 * Preserves in-progress policy drafts and current route state.
 */

import React from 'react';
import { Lock, ShieldAlert, ArrowRight, LogOut } from 'lucide-react';

interface SessionTimeoutModalProps {
  isOpen: boolean;
  userName: string;
  onRenew: () => void;
  onLogout: () => void;
}

export const SessionTimeoutModal: React.FC<SessionTimeoutModalProps> = ({
  isOpen,
  userName,
  onRenew,
  onLogout,
}) => {
  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="timeout-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-space-md bg-grey-50/80 backdrop-blur-sm animate-fade-in"
    >
      <div className="w-full max-w-md bg-grey-100 border border-grey-300 rounded-radius-lg shadow-xl p-space-lg text-grey-900">
        <div className="flex items-center gap-space-sm mb-space-md text-warning-500">
          <div className="w-10 h-10 rounded-radius-full bg-warning-100/30 border border-warning-300 flex items-center justify-center">
            <Lock className="w-5 h-5 text-warning-500" />
          </div>
          <div>
            <h3 id="timeout-modal-title" className="text-base font-bold text-grey-900">
              Session Locked (NFR-029)
            </h3>
            <p className="text-xs text-grey-500">15-minute inactivity security threshold reached</p>
          </div>
        </div>

        <div className="p-space-sm rounded-radius-md bg-grey-200 border border-grey-300 mb-space-lg text-xs space-y-1.5">
          <div className="flex items-center gap-1.5 text-grey-700 font-medium">
            <ShieldAlert className="w-3.5 h-3.5 text-warning-500" />
            <span>Active Operator: <strong className="text-grey-900">{userName}</strong></span>
          </div>
          <p className="text-grey-500 leading-relaxed">
            AegisMCP administrative access is automatically suspended after 15 minutes of idle time. Your active screen state and draft configurations have been preserved.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-end gap-space-sm">
          <button
            type="button"
            onClick={onLogout}
            data-testid="timeout-logout-button"
            className="w-full sm:w-auto px-space-md py-2 rounded-radius-md text-xs font-semibold text-grey-600 hover:text-grey-900 hover:bg-grey-200 transition-colors flex items-center justify-center gap-1.5"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>Sign Out</span>
          </button>

          <button
            type="button"
            onClick={onRenew}
            data-testid="timeout-renew-button"
            className="w-full sm:w-auto px-space-lg py-2 rounded-radius-md text-xs font-bold bg-primary-600 hover:bg-primary-500 text-grey-900 shadow-sm transition-all flex items-center justify-center gap-1.5"
          >
            <span>Resume Session</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};
