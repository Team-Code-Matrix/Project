import React from 'react';
import type { FastPathVerdict } from '../../types/backend';
import { RiskScoreAdapter } from '../../utils/riskScoreAdapter';
import {
  Zap,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  Clock,
  Layers,
  Database,
} from 'lucide-react';

interface FastPathVerdictCardProps {
  fastPath: FastPathVerdict;
  hostname: string;
}

export const FastPathVerdictCard: React.FC<FastPathVerdictCardProps> = ({
  fastPath,
  hostname,
}) => {
  const { label, badgeClass, isPkiCompromised } = RiskScoreAdapter.getVerdictPresentation(
    fastPath.preliminaryVerdict
  );

  return (
    <div className="glass-panel rounded-2xl p-4 md:p-5 border border-shield-border/80 shadow-clay-sm animate-fadeIn text-left">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-shield-border/50 gap-2">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-shield-accent/20 border border-shield-accent/30 text-shield-accent-light">
            <Zap className="w-4 h-4 text-shield-accent-light" />
          </div>
          <div>
            <span className="text-xs font-mono uppercase tracking-wider text-shield-accent-light font-bold">
              Fast-Path Synchronous Lane
            </span>
            <span className="text-xs text-shield-text-muted ml-2 font-mono">
              (&lt;150ms Pre-Detonation Verdict)
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-[11px] font-mono text-shield-text-muted flex items-center gap-1">
            <Clock className="w-3 h-3 text-shield-accent-light" />
            {fastPath.evaluatedInMs}ms
          </span>
          <span
            className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-medium border uppercase ${badgeClass}`}
          >
            {label}
          </span>
        </div>
      </div>

      <p className="text-xs md:text-sm text-shield-text-secondary mt-3 leading-relaxed">
        {fastPath.summary}
      </p>

      {/* Synchronous Filter Matrix Badges */}
      <div className="mt-3.5 pt-3 border-t border-shield-border/40 grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-[11px] font-mono">
        <div className="p-2 rounded-lg bg-shield-surface/80 border border-shield-border/40 flex flex-col">
          <span className="text-shield-text-muted">Redis Bloom / Cuckoo</span>
          <span
            className={`font-semibold mt-0.5 truncate ${
              fastPath.bloomFilterHit ? 'text-shield-danger' : 'text-shield-success'
            }`}
          >
            {fastPath.bloomFilterHit ? `HIT (${fastPath.bloomSource || 'URLhaus'})` : 'CLEAN (0 match)'}
          </span>
        </div>

        <div className="p-2 rounded-lg bg-shield-surface/80 border border-shield-border/40 flex flex-col">
          <span className="text-shield-text-muted">Google Safe Browsing</span>
          <span
            className={`font-semibold mt-0.5 truncate ${
              fastPath.googleSafeBrowsingMatch ? 'text-shield-danger' : 'text-shield-success'
            }`}
          >
            {fastPath.googleSafeBrowsingMatch ? `FLAGGED (${fastPath.gsbThreatType || 'MALWARE'})` : 'CLEAN'}
          </span>
        </div>

        <div className="p-2 rounded-lg bg-shield-surface/80 border border-shield-border/40 flex flex-col">
          <span className="text-shield-text-muted">Mozilla OneCRL</span>
          <span
            className={`font-semibold mt-0.5 truncate ${
              fastPath.mozillaOneCrlRevoked ? 'text-shield-danger' : 'text-shield-success'
            }`}
          >
            {fastPath.mozillaOneCrlRevoked ? 'REVOKED CA' : 'VALID'}
          </span>
        </div>

        <div className="p-2 rounded-lg bg-shield-surface/80 border border-shield-border/40 flex flex-col">
          <span className="text-shield-text-muted">Cached Domain Rep</span>
          <span
            className={`font-semibold mt-0.5 truncate ${
              fastPath.cachedReputation === 'MALICIOUS'
                ? 'text-shield-danger'
                : fastPath.cachedReputation === 'SUSPICIOUS'
                ? 'text-shield-warning'
                : 'text-shield-text-primary'
            }`}
          >
            {fastPath.cachedReputation || 'FRESH SCAN'}
          </span>
        </div>
      </div>
    </div>
  );
};

