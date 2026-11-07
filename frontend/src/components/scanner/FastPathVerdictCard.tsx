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
    <div className="rounded-2xl p-4 md:p-5 bg-gradient-to-br from-white/[0.04] via-[#101713]/40 to-[#080B09]/45 backdrop-blur-[3px] border border-[rgba(120,135,124,0.28)] hover:border-[#F3D081]/40 shadow-[0_15px_35px_rgba(0,0,0,0.5)] animate-fadeIn text-left transition-all">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-[rgba(120,135,124,0.22)] gap-2">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-[#141D18]/70 backdrop-blur-[2px] border border-[rgba(120,135,124,0.3)] text-[#F3D081]">
            <Zap className="w-4 h-4 text-[#F3D081]" />
          </div>
          <div>
            <span className="text-xs font-mono uppercase tracking-wider text-[#F3D081] font-bold">
              FAST-PATH SYNCHRONOUS LANE
            </span>
            <span className="text-xs text-[#78877C] ml-2 font-mono">
              (&lt;150ms Pre-Detonation Verdict)
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-[11px] font-mono text-[#78877C] flex items-center gap-1">
            <Clock className="w-3 h-3 text-[#F3D081]" />
            {fastPath.evaluatedInMs}ms
          </span>
          <span
            className={`px-2.5 py-0.5 rounded font-mono text-[10px] font-bold border uppercase tracking-wider ${badgeClass}`}
          >
            {label}
          </span>
        </div>
      </div>

      <p className="text-xs md:text-sm text-[#B7C4B8] mt-3 leading-relaxed">
        {fastPath.summary}
      </p>

      {/* Synchronous Filter Matrix Badges */}
      <div className="mt-3.5 pt-3 border-t border-[rgba(120,135,124,0.22)] grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-[11px] font-mono">
        <div className="p-2 rounded-lg bg-[#080B09]/60 backdrop-blur-[2px] border border-[rgba(120,135,124,0.25)] flex flex-col">
          <span className="text-[#78877C] text-[10px] uppercase">Redis Bloom / Cuckoo</span>
          <span
            className={`font-semibold mt-0.5 truncate ${
              fastPath.bloomFilterHit ? 'text-rose-400' : 'text-[#78B58D]'
            }`}
          >
            {fastPath.bloomFilterHit ? `HIT (${fastPath.bloomSource || 'URLhaus'})` : 'CLEAN (0 match)'}
          </span>
        </div>

        <div className="p-2 rounded-lg bg-[#080B09]/60 backdrop-blur-[2px] border border-[rgba(120,135,124,0.25)] flex flex-col">
          <span className="text-[#78877C] text-[10px] uppercase">Google Safe Browsing</span>
          <span
            className={`font-semibold mt-0.5 truncate ${
              fastPath.googleSafeBrowsingMatch ? 'text-rose-400' : 'text-[#78B58D]'
            }`}
          >
            {fastPath.googleSafeBrowsingMatch ? `FLAGGED (${fastPath.gsbThreatType || 'MALWARE'})` : 'CLEAN'}
          </span>
        </div>

        <div className="p-2 rounded-lg bg-[#080B09]/60 backdrop-blur-[2px] border border-[rgba(120,135,124,0.25)] flex flex-col">
          <span className="text-[#78877C] text-[10px] uppercase">Mozilla OneCRL</span>
          <span
            className={`font-semibold mt-0.5 truncate ${
              fastPath.mozillaOneCrlRevoked ? 'text-rose-400' : 'text-[#78B58D]'
            }`}
          >
            {fastPath.mozillaOneCrlRevoked ? 'REVOKED CA' : 'VALID'}
          </span>
        </div>

        <div className="p-2 rounded-lg bg-[#080B09]/60 backdrop-blur-[2px] border border-[rgba(120,135,124,0.25)] flex flex-col">
          <span className="text-[#78877C] text-[10px] uppercase">Cached Domain Rep</span>
          <span
            className={`font-semibold mt-0.5 truncate ${
              fastPath.cachedReputation === 'MALICIOUS'
                ? 'text-rose-400'
                : fastPath.cachedReputation === 'SUSPICIOUS'
                ? 'text-amber-400'
                : 'text-[#E9E6DC]'
            }`}
          >
            {fastPath.cachedReputation || 'FRESH SCAN'}
          </span>
        </div>
      </div>
    </div>
  );
};

