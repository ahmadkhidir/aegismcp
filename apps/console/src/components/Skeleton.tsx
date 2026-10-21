import React from 'react';

interface SkeletonProps {
  className?: string;
}

export const Skeleton: React.FC<SkeletonProps> = ({ className = '' }) => {
  return (
    <div
      role="status"
      aria-label="Loading content"
      className={`animate-pulse bg-grey-200 rounded-radius-md ${className}`}
    />
  );
};
