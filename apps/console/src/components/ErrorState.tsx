import React from 'react';
import { AlertTriangle, RotateCw } from 'lucide-react';

interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'Telemetry Connection Error',
  message,
  onRetry,
}) => {
  return (
    <div
      data-testid="error-state"
      role="alert"
      className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-space-md bg-error-100 border border-error-300 rounded-radius-lg my-space-md gap-space-md text-error-900"
    >
      <div className="flex items-start gap-space-sm">
        <AlertTriangle className="w-6 h-6 text-error-500 flex-shrink-0 mt-0.5" />
        <div>
          <h4 className="font-semibold text-sm text-error-900">{title}</h4>
          <p className="text-xs text-error-700 mt-0.5">{message}</p>
        </div>
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          data-testid="retry-button"
          className="inline-flex items-center gap-1.5 px-space-md py-space-xs bg-error-500 hover:bg-error-400 text-grey-900 font-medium text-xs rounded-radius-md transition-colors flex-shrink-0"
        >
          <RotateCw className="w-3.5 h-3.5" />
          <span>Retry Connection</span>
        </button>
      )}
    </div>
  );
};
