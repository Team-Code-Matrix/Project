import { RiskLevel, ModelVerdict, FindingSeverity } from '../types/scan';

export function getRiskLabel(riskLevel: RiskLevel): string {
  switch (riskLevel) {
    case 'low':
      return 'Lower observed risk';
    case 'caution':
      return 'Caution';
    case 'high':
      return 'High risk';
    case 'critical':
      return 'Critical risk';
    case 'insufficient_data':
      return 'Insufficient data';
    default:
      return 'Unrated';
  }
}

export function getRiskColorClass(riskLevel: RiskLevel): {
  badge: string;
  text: string;
  bg: string;
  border: string;
  stroke: string;
} {
  switch (riskLevel) {
    case 'low':
      return {
        badge: 'bg-shield-success/15 text-shield-success border-shield-success/30',
        text: 'text-shield-success',
        bg: 'bg-shield-success/10',
        border: 'border-shield-success/40',
        stroke: '#78B58D',
      };
    case 'caution':
      return {
        badge: 'bg-shield-warning/15 text-shield-warning border-shield-warning/30',
        text: 'text-shield-warning',
        bg: 'bg-shield-warning/10',
        border: 'border-shield-warning/40',
        stroke: '#D7AA62',
      };
    case 'high':
      return {
        badge: 'bg-amber-600/15 text-amber-400 border-amber-600/30',
        text: 'text-amber-400',
        bg: 'bg-amber-600/10',
        border: 'border-amber-600/40',
        stroke: '#EA580C',
      };
    case 'critical':
      return {
        badge: 'bg-shield-danger/20 text-shield-danger border-shield-danger/40',
        text: 'text-shield-danger',
        bg: 'bg-shield-danger/10',
        border: 'border-shield-danger/40',
        stroke: '#D97878',
      };
    case 'insufficient_data':
    default:
      return {
        badge: 'bg-slate-700/30 text-shield-text-secondary border-slate-600/30',
        text: 'text-shield-text-secondary',
        bg: 'bg-slate-800/20',
        border: 'border-slate-700/30',
        stroke: '#9AA9A0',
      };
  }
}

export function getVerdictBadgeClass(verdict: ModelVerdict): string {
  switch (verdict) {
    case 'clear':
      return 'bg-emerald-950/40 text-emerald-300 border-emerald-500/25';
    case 'suspicious':
      return 'bg-amber-950/40 text-amber-300 border-amber-500/30';
    case 'malicious':
      return 'bg-rose-950/50 text-rose-300 border-rose-500/40';
    case 'skipped':
      return 'bg-slate-900/60 text-slate-400 border-slate-700/30';
    case 'error':
      return 'bg-red-950/40 text-red-400 border-red-500/30';
    case 'unknown':
    default:
      return 'bg-slate-900/40 text-slate-300 border-slate-700/25';
  }
}

export function getSeverityBadgeClass(severity: FindingSeverity): {
  badge: string;
  pill: string;
  iconColor: string;
} {
  switch (severity) {
    case 'critical':
      return {
        badge: 'bg-rose-950/50 text-rose-300 border-rose-500/40',
        pill: 'bg-rose-500',
        iconColor: 'text-rose-400',
      };
    case 'high':
      return {
        badge: 'bg-amber-950/40 text-amber-300 border-amber-500/35',
        pill: 'bg-amber-500',
        iconColor: 'text-amber-400',
      };
    case 'medium':
      return {
        badge: 'bg-yellow-950/30 text-yellow-300 border-yellow-500/30',
        pill: 'bg-yellow-500',
        iconColor: 'text-yellow-400',
      };
    case 'low':
      return {
        badge: 'bg-emerald-950/30 text-emerald-300 border-emerald-500/25',
        pill: 'bg-emerald-500',
        iconColor: 'text-emerald-400',
      };
    case 'informational':
    default:
      return {
        badge: 'bg-sky-950/30 text-sky-300 border-sky-500/25',
        pill: 'bg-sky-500',
        iconColor: 'text-sky-400',
      };
  }
}

export function formatTimestamp(isoString: string): string {
  try {
    const d = new Date(isoString);
    return d.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZoneName: 'short',
    });
  } catch {
    return isoString;
  }
}

