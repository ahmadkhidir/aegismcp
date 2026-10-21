import React from 'react';
import { LucideIcon, Inbox } from 'lucide-react';

interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon: Icon = Inbox,
  title,
  description,
  actionLabel,
  onAction,
}) => {
  return (
    <div
      data-testid="empty-state"
      className="flex flex-col items-center justify-center p-space-xl text-center border border-grey-300 bg-grey-100 rounded-radius-lg my-space-md"
    >
      <div className="p-space-md rounded-radius-full bg-grey-200 text-grey-400 mb-space-md">
        <Icon className="w-12 h-12" aria-hidden="true" />
      </div>
      <h3 className="text-lg font-semibold text-grey-900 mb-space-xs">{title}</h3>
      <p className="text-sm text-grey-500 max-w-md mb-space-md">{description}</p>
      {actionLabel && onAction && (
        <button
          onClick={onAction}
          className="px-space-md py-space-sm bg-primary-500 hover:bg-primary-600 text-grey-900 font-medium text-sm rounded-radius-md transition-colors"
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
};
