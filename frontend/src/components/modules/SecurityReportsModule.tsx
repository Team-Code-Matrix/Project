import React from 'react';
import {
  FileText,
  Printer,
  Download,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Share2,
} from 'lucide-react';
import type { ScanResult } from '../../types/scan';
import type { ExtendedScanReport } from '../../types/backend';
import { RiskBadge } from '../shared/RiskBadge';
import { SeverityBadge } from '../shared/SeverityBadge';

export interface SecurityReportsModuleProps {
  result: ScanResult;
  extendedReport?: ExtendedScanReport | null;
}

export const SecurityReportsModule: React.FC<SecurityReportsModuleProps> = ({
  result,
  extendedReport,
}) => {
  const handlePrint = () => {
    window.print();
  };

  const handleDownloadJson = () => {
    const reportData = extendedReport || result;
    const blob = new Blob([JSON.stringify(reportData, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `trustshield-report-${result.hostname}-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 text-left">
      {/* Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-[#0D1410] border border-shield-border/80">
        <div>
          <span className="text-xs font-mono text-shield-accent-light uppercase tracking-wider">
            Consolidated Security Report
          </span>
          <h2 className="text-lg md:text-xl font-bold text-shield-text-primary">
            Executive Intelligence Brief for {result.hostname}
          </h2>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handlePrint}
            className="px-3.5 py-2 rounded-xl bg-shield-surface border border-shield-border hover:border-shield-accent text-xs font-mono text-shield-text-primary flex items-center gap-2 cursor-pointer transition-colors"
          >
            <Printer className="w-4 h-4 text-shield-accent-light" />
            <span>Print Report</span>
          </button>

          <button
            type="button"
            onClick={handleDownloadJson}
            className="px-3.5 py-2 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 text-[#080B09] font-mono font-bold text-xs flex items-center gap-2 shadow-clay-sm hover:scale-[1.02] active:scale-[0.98] transition-all cursor-pointer"
          >
            <Download className="w-4 h-4 text-[#080B09]" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Score & Verdict Bento Card */}
      <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
        <div className="space-y-2">
          <span className="text-xs font-mono text-shield-text-muted uppercase">Verdict & Trust Score</span>
          <div className="flex items-baseline gap-3">
            <span className="text-5xl font-black text-shield-text-primary">{result.score}</span>
            <span className="text-sm font-mono text-shield-text-muted">/ 100</span>
          </div>
          <RiskBadge level={result.riskLevel} />
        </div>

        <div className="md:col-span-2 space-y-2 border-t md:border-t-0 md:border-l border-shield-border/50 pt-4 md:pt-0 md:pl-6">
          <span className="text-xs font-mono text-shield-accent-light uppercase">Executive Summary</span>
          <p className="text-sm text-shield-text-secondary leading-relaxed">{result.summary}</p>
          {result.criticalOverride && (
            <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs font-mono">
              ⚠ Critical Override Active: {result.overrideReason}
            </div>
          )}
        </div>
      </div>

      {/* Security Findings Breakdown */}
      <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-shield-border/60">
          <h3 className="text-base font-bold text-shield-text-primary">Observed Security Findings ({result.findings.length})</h3>
          <span className="text-xs font-mono text-shield-text-muted">Ranked by risk severity</span>
        </div>

        <div className="space-y-3 font-mono text-xs">
          {result.findings.map((f) => (
            <div
              key={f.id}
              className="p-4 rounded-2xl bg-[#0D1410] border border-shield-border/60 space-y-2"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <span className="font-bold text-sm text-shield-text-primary">{f.title}</span>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-shield-surface text-[10px] text-shield-text-muted">
                    {f.source}
                  </span>
                  <SeverityBadge severity={f.severity} />
                </div>
              </div>
              <p className="text-xs text-shield-text-secondary leading-relaxed">{f.description}</p>
              {f.recommendation && (
                <div className="p-2.5 rounded-xl bg-shield-surface text-[11px] text-shield-accent-light border border-shield-border/40">
                  Recommendation: {f.recommendation}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Recommended Protective Actions */}
      <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-4">
        <h3 className="text-base font-bold text-shield-text-primary">Recommended Protective Actions</h3>
        <div className="space-y-2 font-mono text-xs">
          {result.recommendedActions.map((act, i) => (
            <div key={i} className="p-3.5 rounded-xl bg-[#0D1410] border border-shield-border/50 flex items-start gap-2.5">
              <span className="text-emerald-400 font-bold shrink-0 mt-0.5">#{i + 1}</span>
              <span className="text-shield-text-secondary">
                <strong className="text-shield-text-primary">{act.title}:</strong> {act.detail}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
