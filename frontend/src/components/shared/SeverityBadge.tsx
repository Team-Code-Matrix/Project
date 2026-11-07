import React from 'react';
import { FindingSeverity } from '../../types/scan';
import { getSeverityBadgeClass } from '../../utils/formatters';
import { AlertCircle, ShieldAlert, AlertTriangle, Info, CheckCircle } from 'lucide-react';

interface SeverityBadgeProps {
  severity: FindingSeverity;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => {
  const { badge, iconColor } = getSeverityBadgeClass(severity);

  const getIcon = () => {
    switch (severity) {
      case 'critical':
        return <ShieldAlert className={`w-3.5 h-3.5 ${iconColor}`} />;
      case 'high':
        return <AlertCircle className={`w-3.5 h-3.5 ${iconColor}`} />;
      case 'medium':
        return <AlertTriangle className={`w-3.5 h-3.5 ${iconColor}`} />;
      case 'low':
        return <CheckCircle className={`w-3.5 h-3.5 ${iconColor}`} />;
      case 'informational':
      default:
        return <Info className={`w-3.5 h-3.5 ${iconColor}`} />;
    }
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-medium border uppercase tracking-wider ${badge}`}
    >
      {getIcon()}
      <span>{severity}</span>
    </span>
  );
};

