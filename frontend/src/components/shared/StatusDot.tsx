import React from 'react';

interface StatusDotProps {
  status: 'online' | 'warning' | 'error' | 'idle';
  label?: string;
  pulse?: boolean;
}

export const StatusDot: React.FC<StatusDotProps> = ({
  status,
  label,
  pulse = true,
}) => {
  const getColors = () => {
    switch (status) {
      case 'online':
        return {
          dot: 'bg-shield-success',
          ring: 'bg-shield-success/30',
        };
      case 'warning':
        return {
          dot: 'bg-shield-warning',
          ring: 'bg-shield-warning/30',
        };
      case 'error':
        return {
          dot: 'bg-shield-danger',
          ring: 'bg-shield-danger/30',
        };
      case 'idle':
      default:
        return {
          dot: 'bg-shield-text-muted',
          ring: 'bg-shield-text-muted/20',
        };
    }
  };

  const { dot, ring } = getColors();

  return (
    <span className="inline-flex items-center gap-2 text-xs font-mono text-shield-text-secondary">
      <span className="relative flex h-2 w-2">
        {pulse && (
          <span
            className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${ring}`}
          />
        )}
        <span className={`relative inline-flex rounded-full h-2 w-2 ${dot}`} />
      </span>
      {label && <span>{label}</span>}
    </span>
  );
};

