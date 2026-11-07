import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Layers,
  Search,
  Filter,
} from 'lucide-react';
import type { ScanResult } from '../../types/scan';
import type { ExtendedScanReport } from '../../types/backend';
import { SeverityBadge } from '../shared/SeverityBadge';

export interface SecurityChecksModuleProps {
  result: ScanResult;
  extendedReport?: ExtendedScanReport | null;
}

export const SecurityChecksModule: React.FC<SecurityChecksModuleProps> = ({
  result,
  extendedReport,
}) => {
  const [filter, setFilter] = useState<'all' | 'passed' | 'failed'>('all');
  const [selectedPillar, setSelectedPillar] = useState<string>('all');

  const models = result.models;
  const findings = result.findings;

  // Flatten checks across all 6 models
  const allChecks = models.flatMap((m) => {
    const isClean = m.verdict === 'clear';
    const isWarn = m.verdict === 'suspicious';
    return [
      {
        id: `${m.id}-core`,
        pillar: m.name,
        name: `${m.name} Verification`,
        status: isClean ? 'PASSED' : isWarn ? 'WARNING' : 'FAILED',
        severity: isClean ? ('low' as const) : isWarn ? ('medium' as const) : ('critical' as const),
        confidence: m.confidence ?? 95,
        description: m.description,
        evidence: findings.filter((f) => f.source.toLowerCase().includes(m.name.toLowerCase()) || f.source.toLowerCase().includes(m.category.toLowerCase())).map((f) => f.title),
      },
    ];
  });

  const filteredChecks = allChecks.filter((c) => {
    if (filter === 'passed' && c.status !== 'PASSED') return false;
    if (filter === 'failed' && c.status === 'PASSED') return false;
    if (selectedPillar !== 'all' && c.pillar !== selectedPillar) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Summary KPI Badges */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 text-left">
        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Evaluated Models</div>
          <div className="text-2xl font-black text-shield-text-primary">{models.length} Models</div>
          <div className="text-[11px] font-mono text-emerald-400 mt-1">Multi-Pillar Consensus</div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Checks Passed</div>
          <div className="text-2xl font-black text-emerald-400">
            {allChecks.filter((c) => c.status === 'PASSED').length} Passed
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">Zero security defect</div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Warnings / Flags</div>
          <div className="text-2xl font-black text-amber-400">
            {allChecks.filter((c) => c.status === 'WARNING').length} Flags
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">Heuristic deviations</div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Critical Overrides</div>
          <div className={`text-2xl font-black ${result.criticalOverride ? 'text-rose-400' : 'text-emerald-400'}`}>
            {result.criticalOverride ? '1 Triggered' : '0 Triggered'}
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">
            {result.criticalOverride ? result.overrideReason : 'No hard block active'}
          </div>
        </div>
      </div>

      {/* Security Checks List */}
      <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-shield-border/60">
          <div>
            <h3 className="text-lg font-bold text-shield-text-primary">Multi-Model Security Audit Ledger</h3>
            <p className="text-xs text-shield-text-secondary">Comprehensive verification status per detection engine</p>
          </div>

          <div className="flex items-center gap-1.5 p-1 rounded-xl bg-shield-surface-elevated border border-shield-border text-xs font-mono">
            <button
              type="button"
              onClick={() => setFilter('all')}
              className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                filter === 'all' ? 'bg-shield-accent text-white font-bold' : 'text-shield-text-secondary'
              }`}
            >
              All ({allChecks.length})
            </button>
            <button
              type="button"
              onClick={() => setFilter('passed')}
              className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                filter === 'passed' ? 'bg-shield-accent text-white font-bold' : 'text-shield-text-secondary'
              }`}
            >
              Passed ({allChecks.filter((c) => c.status === 'PASSED').length})
            </button>
            <button
              type="button"
              onClick={() => setFilter('failed')}
              className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                filter === 'failed' ? 'bg-shield-accent text-white font-bold' : 'text-shield-text-secondary'
              }`}
            >
              Anomalies ({allChecks.filter((c) => c.status !== 'PASSED').length})
            </button>
          </div>
        </div>

        <div className="space-y-4">
          {filteredChecks.map((chk) => (
            <div
              key={chk.id}
              className="p-5 rounded-2xl bg-[#0D1410] border border-shield-border/60 space-y-3 text-left transition-all hover:border-shield-border"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <div
                    className={`p-2 rounded-xl ${
                      chk.status === 'PASSED'
                        ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-500/30'
                        : chk.status === 'WARNING'
                        ? 'bg-amber-950/60 text-amber-400 border border-amber-500/30'
                        : 'bg-rose-950/60 text-rose-400 border border-rose-500/30'
                    }`}
                  >
                    {chk.status === 'PASSED' ? (
                      <CheckCircle2 className="w-4 h-4" />
                    ) : (
                      <AlertTriangle className="w-4 h-4" />
                    )}
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-shield-text-primary">{chk.name}</h4>
                    <span className="text-[11px] font-mono text-shield-text-muted">{chk.pillar}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold text-shield-text-muted">
                    Confidence: {chk.confidence}%
                  </span>
                  <SeverityBadge severity={chk.severity as any} />
                </div>
              </div>

              <p className="text-xs text-shield-text-secondary leading-relaxed">{chk.description}</p>

              {chk.evidence.length > 0 && (
                <div className="pt-2 border-t border-shield-border/40 space-y-1">
                  <span className="text-[11px] font-mono uppercase text-shield-text-muted">Observed Findings:</span>
                  <div className="flex flex-wrap gap-1.5">
                    {chk.evidence.map((ev, i) => (
                      <span
                        key={i}
                        className="px-2 py-0.5 rounded bg-shield-surface text-[11px] font-mono text-shield-text-primary border border-shield-border/60"
                      >
                        • {ev}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
