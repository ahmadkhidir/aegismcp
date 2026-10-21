import React from 'react';
import { WifiOff } from 'lucide-react';

interface OfflineBannerProps {
  isOffline: boolean;
}

export const OfflineBanner: React.FC<OfflineBannerProps> = ({ isOffline }) => {
  if (!isOffline) return null;

  return (
    <div
      data-testid="offline-banner"
      role="status"
      className="w-full bg-warning-500 text-grey-50 px-space-md py-1.5 flex items-center justify-center gap-2 font-medium text-xs tracking-wide sticky top-0 z-50 shadow-md"
    >
      <WifiOff className="w-4 h-4 animate-pulse" />
      <span>Offline — browser connection lost. Telemetry paused.</span>
    </div>
  );
};
