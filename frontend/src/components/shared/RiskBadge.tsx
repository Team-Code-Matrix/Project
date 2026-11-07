import React from 'react';
import { RiskLevel } from '../../types/scan';
import { getRiskLabel, getRiskColorClass } from '../../utils/formatters';
import { ShieldCheck, AlertTriangle, AlertOctagon, ShieldAlert, HelpCircle } from 'lucide-react';

interface RiskBadgeProps {
  level: RiskLevel;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({
  level,
  size = 'md',
  showIcon = true,
}) => {
  const label = getRiskLabel(level);
  const color = getRiskColorClass(level);

  const getIcon = () => {
    switch (level) {
      case 'low':
        return <ShieldCheck className="w-4 h-4 text-shield-success" />;
      case 'caution':
        return <AlertTriangle className="w-4 h-4 text-shield-warning" />;
      case 'high':
        return <AlertOctagon className="w-4 h-4 text-amber-400" />;
      case 'critical':
        return <ShieldAlert className="w-4 h-4 text-shield-danger" />;
      case 'insufficient_data':
      default:
        return <HelpCircle className="w-4 h-4 text-shield-text-secondary" />;
    }
  };

  const sizeClasses = {
    sm: 'text-xs px-2.5 py-0.5 gap-1.5',
    md: 'text-xs md:text-sm px-3 py-1 gap-2 font-medium',
    lg: 'text-sm md:text-base px-4 py-1.5 gap-2.5 font-semibold tracking-wide',
  };

  return (
    <span
      className={`inline-flex items-center rounded-full border transition-all ${color.badge} ${sizeClasses[size]}`}
    >
      {showIcon && getIcon()}
      <span>{label}</span>
    </span>
  );
};

