import React from 'react';
import { ModelVerdict } from '../../types/scan';
import { getVerdictBadgeClass } from '../../utils/formatters';
import { CheckCircle2, AlertTriangle, XCircle, HelpCircle, MinusCircle } from 'lucide-react';

interface VerdictBadgeProps {
  verdict: ModelVerdict;
}

export const VerdictBadge: React.FC<VerdictBadgeProps> = ({ verdict }) => {
  const badgeClass = getVerdictBadgeClass(verdict);

  const renderIcon = () => {
    switch (verdict) {
      case 'clear':
        return <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />;
      case 'suspicious':
        return <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />;
      case 'malicious':
        return <XCircle className="w-3.5 h-3.5 text-rose-400" />;
      case 'skipped':
        return <MinusCircle className="w-3.5 h-3.5 text-slate-400" />;
      case 'error':
        return <XCircle className="w-3.5 h-3.5 text-red-400" />;
      case 'unknown':
      default:
        return <HelpCircle className="w-3.5 h-3.5 text-slate-400" />;
    }
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-medium border uppercase tracking-wider ${badgeClass}`}
    >
      {renderIcon()}
      <span>{verdict}</span>
    </span>
  );
};

