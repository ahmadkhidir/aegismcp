import React, { useState } from 'react';
import { AlertOctagon, X, Loader2 } from 'lucide-react';
import { EmergencyKillRequest, EmergencyKillResponse } from '../types/contracts';

interface KillSwitchModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (req: EmergencyKillRequest) => Promise<EmergencyKillResponse>;
}

export const KillSwitchModal: React.FC<KillSwitchModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
}) => {
  const [targetType, setTargetType] = useState<EmergencyKillRequest['targetType']>('global');
  const [targetId, setTargetId] = useState('');
  const [reason, setReason] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmedTyped, setConfirmedTyped] = useState('');

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (confirmedTyped !== 'LOCKDOWN') {
      setError('Please type LOCKDOWN to confirm trip circuit breaker');
      return;
    }
    if (targetType !== 'global' && !targetId.trim()) {
      setError('Enter the session, agent, or server identifier for this scope.');
      return;
    }
    if (!reason.trim()) {
      setError('A justification reason is required for audit compliance');
      return;
    }

    setError(null);
    setIsSubmitting(true);
    try {
      await onConfirm({
        targetType,
        ...(targetType === 'global' ? {} : { targetId: targetId.trim() }),
        reason: reason.trim(),
      });
      setIsSubmitting(false);
      onClose();
    } catch (err: unknown) {
      setIsSubmitting(false);
      setError(err instanceof Error ? err.message : 'Failed to trip emergency kill switch');
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="kill-switch-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-space-md bg-grey-50/80 backdrop-blur-sm"
    >
      <div className="w-full max-w-lg bg-grey-100 border border-error-300 rounded-radius-lg shadow-xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        <div className="flex items-center justify-between p-space-md bg-error-100 border-b border-error-300 text-error-900">
          <div className="flex items-center gap-space-sm">
            <div className="p-2 rounded-radius-full bg-error-500 text-grey-900">
              <AlertOctagon className="w-5 h-5" />
            </div>
            <div>
              <h3 id="kill-switch-title" className="font-bold text-body text-error-900">
                Emergency Cluster Kill-Switch
              </h3>
              <p className="text-caption text-error-700">Immediate traffic severance & agent quarantine</p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="p-1 rounded-radius-sm text-error-700 hover:text-error-900 hover:bg-error-300/20"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-space-lg space-y-space-md">
          {error && (
            <div role="alert" className="p-space-sm bg-error-100 border border-error-300 text-error-900 rounded-radius-md text-caption">
              {error}
            </div>
          )}

          <div>
            <label className="block text-caption font-semibold text-grey-700 mb-1">
              Target Scope
            </label>
            <select
              value={targetType}
              onChange={(e) => {
                setTargetType(e.target.value as EmergencyKillRequest['targetType']);
                setTargetId('');
              }}
              className="w-full bg-grey-200 border border-grey-300 rounded-radius-md px-space-sm py-2 text-caption text-grey-900 focus:border-primary-500 outline-none"
            >
              <option value="global">Global (Sever every agent session cluster-wide)</option>
              <option value="agent">Agent (Quarantine a specific SPIFFE identity)</option>
              <option value="session">Session (Close one transport session)</option>
              <option value="server">Server (Sever an upstream MCP server endpoint)</option>
            </select>
          </div>

          <div>
            <label className="block text-caption font-semibold text-grey-700 mb-1">
              Target Identifier
            </label>
            <input
              type="text"
              value={targetId}
              onChange={(e) => setTargetId(e.target.value)}
              required={targetType !== 'global'}
              disabled={targetType === 'global'}
              className="w-full bg-grey-200 border border-grey-300 rounded-radius-md px-space-sm py-2 text-caption font-mono text-grey-900 focus:border-primary-500 outline-none disabled:opacity-50"
              placeholder={
                targetType === 'global'
                  ? 'Cluster-wide scope'
                  : targetType === 'agent'
                  ? 'spiffe://...'
                  : targetType === 'session'
                  ? 'Session identifier'
                  : 'Upstream server identifier'
              }
            />
          </div>

          <div>
            <label className="block text-caption font-semibold text-grey-700 mb-1">
              Security Justification (Required for Tamper-Evident Ledger)
            </label>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              required
              rows={2}
              className="w-full bg-grey-200 border border-grey-300 rounded-radius-md px-space-sm py-2 text-caption text-grey-900 focus:border-primary-500 outline-none resize-none"
              placeholder="e.g. Active prompt injection chain detected across billing cluster..."
            />
          </div>

          <div className="p-space-sm bg-grey-200 border border-grey-300 rounded-radius-md text-caption">
            <p className="text-grey-600 mb-2">
              Type <span className="font-bold font-mono text-error-500">LOCKDOWN</span> below to confirm:
            </p>
            <input
              type="text"
              data-testid="lockdown-confirm-input"
              value={confirmedTyped}
              onChange={(e) => setConfirmedTyped(e.target.value)}
              className="w-full bg-grey-100 border border-grey-300 rounded-radius-md px-space-sm py-1.5 text-caption font-mono font-bold text-error-500 focus:border-error-500 outline-none uppercase"
              placeholder="LOCKDOWN"
            />
          </div>

          <div className="flex items-center justify-end gap-space-sm pt-space-xs border-t border-grey-300">
            <button
              type="button"
              onClick={onClose}
              disabled={isSubmitting}
              className="px-space-md py-space-sm rounded-radius-md text-caption font-medium text-grey-600 hover:text-grey-900 hover:bg-grey-200 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              data-testid="trip-killswitch-button"
              disabled={isSubmitting || confirmedTyped !== 'LOCKDOWN'}
              className="inline-flex items-center gap-1.5 px-space-md py-space-sm rounded-radius-md text-caption font-bold bg-error-500 hover:bg-error-700 text-grey-900 transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-md"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Severing Traffic...</span>
                </>
              ) : (
                <>
                  <AlertOctagon className="w-3.5 h-3.5" />
                  <span>Trip Kill-Switch</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
