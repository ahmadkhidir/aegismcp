import React from 'react';
import { CheckCircle2, ShieldAlert, Clock, AlertOctagon } from 'lucide-react';
import { EventVerdict } from '../types/contracts';

interface StatusPillProps {
  verdict: EventVerdict | string;
  size?: 'sm' | 'md';
}

export const StatusPill: React.FC<StatusPillProps> = ({ verdict, size = 'sm' }) => {
  const norm = verdict.toUpperCase();
  const iconSize = size === 'sm' ? 12 : 16;
  const textSize = size === 'sm' ? 'text-xs' : 'text-sm';
  const padding = size === 'sm' ? 'px-space-xs py-0.5' : 'px-space-sm py-1';

  if (norm === 'ALLOWED' || norm === 'PASS' || norm === 'APPROVED') {
    return (
      <span
        data-testid="status-pill-allowed"
        className={`inline-flex items-center gap-1.5 font-mono font-medium rounded-radius-full bg-success-100 text-success-900 border border-success-300 ${padding} ${textSize}`}
      >
        <CheckCircle2 size={iconSize} className="text-success-500" />
        <span>ALLOWED</span>
      </span>
    );
  }

  if (norm === 'BLOCKED' || norm === 'REJECTED') {
    return (
      <span
        data-testid="status-pill-blocked"
        className={`inline-flex items-center gap-1.5 font-mono font-medium rounded-radius-full bg-error-100 text-error-900 border border-error-300 ${padding} ${textSize}`}
      >
        <ShieldAlert size={iconSize} className="text-error-500" />
        <span>BLOCKED</span>
      </span>
    );
  }

  if (norm === 'PENDING_APPROVAL' || norm === 'PENDING' || norm === 'PENDING_HITL' || norm === 'REQUIRE_APPROVAL') {
    return (
      <span
        data-testid="status-pill-pending"
        className={`inline-flex items-center gap-1.5 font-mono font-medium rounded-radius-full bg-warning-100 text-warning-900 border border-warning-300 ${padding} ${textSize}`}
      >
        <Clock size={iconSize} className="text-warning-500" />
        <span>{norm === 'REQUIRE_APPROVAL' ? 'REQUIRE_APPROVAL' : 'PENDING HITL'}</span>
      </span>
    );
  }

  return (
    <span
      data-testid="status-pill-quarantined"
      className={`inline-flex items-center gap-1.5 font-mono font-semibold rounded-radius-full bg-error-900 text-grey-900 border border-error-500 ${padding} ${textSize}`}
    >
      <AlertOctagon size={iconSize} className="text-error-400" />
      <span>QUARANTINED</span>
    </span>
  );
};
