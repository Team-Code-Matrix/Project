import React, { useState } from 'react';
import type { ScanResult } from '../../types/scan';
import { formatTimestamp } from '../../utils/formatters';
import {
  Share2,
  Check,
  RotateCcw,
  Shield,
  Layers,
  Clock,
  CheckCircle,
  AlertCircle,
  HelpCircle,
  Download,
  Printer,
} from 'lucide-react';

interface DashboardHeaderProps {
  scanResult: ScanResult;
  onReset: () => void;
  onOpenMethodology: () => void;
}

export const DashboardHeader: React.FC<DashboardHeaderProps> = ({
  scanResult,
  onReset,
  onOpenMethodology,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopySummary = async () => {
    const summaryText = `[Trust Shield Assessment]
Target: ${scanResult.hostname} (${scanResult.submittedUrl})
Trust Score: ${scanResult.score ?? 'N/A'}/100 (${scanResult.riskLevel.toUpperCase()})
Checked At: ${scanResult.checkedAt}
Summary: ${scanResult.summary}
Evaluated via Trust Shield Multi-Model Engine.`;

    try {
      await navigator.clipboard.writeText(summaryText);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      // Fallback
    }
  };

  const handleDownloadJson = () => {
    const jsonStr = JSON.stringify(scanResult, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `trust-shield-report-${scanResult.hostname.replace(/[^a-z0-9]/gi, '_')}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="rounded-2xl p-6 md:p-8 bg-[#101713]/90 border border-[rgba(120,135,124,0.3)] shadow-[0_20px_50px_rgba(0,0,0,0.6)] text-left relative">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-[rgba(120,135,124,0.25)]">
        <div className="space-y-2.5">
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#080B09] border border-[rgba(120,135,124,0.3)] text-[10px] font-mono font-bold text-[#F3D081] uppercase tracking-wider">
              <Shield className="w-3.5 h-3.5" />
              SCAN_ID: {scanResult.scanId}
            </span>

            {scanResult.isDemo && (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-amber-950/40 border border-amber-600/30 text-[10px] font-mono text-amber-300 uppercase tracking-wider">
                DEMO_SANDBOX
              </span>
            )}

            <button
              type="button"
              onClick={onOpenMethodology}
              className="text-xs font-mono text-[#B7C4B8] hover:text-[#F3D081] underline underline-offset-4 transition-colors cursor-pointer"
            >
              How score is calculated?
            </button>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-baseline gap-2">
            <h1 className="text-2xl md:text-3xl lg:text-4xl font-black font-sans text-[#E9E6DC] tracking-tight uppercase">
              {scanResult.hostname}
            </h1>
            <span className="text-xs font-mono text-[#78877C] truncate max-w-lg">
              ({scanResult.submittedUrl})
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-4 text-xs font-mono text-[#78877C]">
            <span className="flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-[#F3D081]" />
              {formatTimestamp(scanResult.checkedAt)}
            </span>
            {scanResult.resolvedIp && (
              <span>
                RESOLVED_IP: <code className="text-[#E9E6DC] font-bold">{scanResult.resolvedIp}</code>
              </span>
            )}
            {scanResult.asn && (
              <span className="truncate max-w-xs text-[#B7C4B8]">{scanResult.asn}</span>
            )}
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={handleCopySummary}
            title="Copy plain-text summary"
            className="px-3.5 py-2.5 rounded-xl text-xs md:text-sm font-mono font-bold tracking-wider uppercase text-[#E9E6DC] bg-[#141D18] border border-[rgba(120,135,124,0.3)] hover:border-[#F3D081] hover:text-[#F3D081] flex items-center gap-1.5 cursor-pointer transition-all"
          >
            {copied ? (
              <>
                <Check className="w-4 h-4 text-[#78B58D]" />
                <span className="text-[#78B58D]">Copied</span>
              </>
            ) : (
              <>
                <Share2 className="w-4 h-4 text-[#F3D081]" />
                <span>Share</span>
              </>
            )}
          </button>

          <button
            type="button"
            onClick={handleDownloadJson}
            title="Download full JSON report"
            className="px-3.5 py-2.5 rounded-xl text-xs md:text-sm font-mono font-bold tracking-wider uppercase text-[#E9E6DC] bg-[#141D18] border border-[rgba(120,135,124,0.3)] hover:border-[#F3D081] hover:text-[#F3D081] flex items-center gap-1.5 cursor-pointer transition-all"
          >
            <Download className="w-4 h-4 text-shield-accent-light" />
            <span>Export JSON</span>
          </button>

          <button
            type="button"
            onClick={handlePrint}
            title="Print assessment report"
            className="clay-button-secondary px-3 py-2.5 rounded-xl text-xs text-shield-text-secondary hover:text-shield-text-primary flex items-center cursor-pointer"
          >
            <Printer className="w-4 h-4" />
          </button>

          <button
            type="button"
            onClick={onReset}
            className="clay-button px-5 py-2.5 rounded-xl text-xs md:text-sm font-bold text-white flex items-center gap-2 cursor-pointer"
          >
            <RotateCcw className="w-4 h-4" />
            <span>Scan Another</span>
          </button>
        </div>
      </div>

      {/* Model Checks Breakdown Counters */}
      <div className="pt-6 grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-3.5 rounded-xl bg-shield-surface/60 border border-shield-border/70">
          <div className="text-xs text-shield-text-muted font-mono mb-1">Checks Completed</div>
          <div className="text-xl font-bold font-mono text-shield-success flex items-center gap-1.5">
            <CheckCircle className="w-4 h-4" />
            <span>{scanResult.checksCompleted} / 6</span>
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-shield-surface/60 border border-shield-border/70">
          <div className="text-xs text-shield-text-muted font-mono mb-1">Skipped / N/A</div>
          <div className="text-xl font-bold font-mono text-shield-text-secondary flex items-center gap-1.5">
            <HelpCircle className="w-4 h-4" />
            <span>{scanResult.checksSkipped}</span>
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-shield-surface/60 border border-shield-border/70">
          <div className="text-xs text-shield-text-muted font-mono mb-1">Check Errors</div>
          <div className="text-xl font-bold font-mono text-shield-text-secondary flex items-center gap-1.5">
            <AlertCircle className="w-4 h-4" />
            <span>{scanResult.checksErrored}</span>
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-shield-surface/60 border border-shield-border/70">
          <div className="text-xs text-shield-text-muted font-mono mb-1">Findings Flagged</div>
          <div className="text-xl font-bold font-mono text-shield-text-primary flex items-center gap-1.5">
            <Layers className="w-4 h-4 text-shield-accent-light" />
            <span>{scanResult.findings.length} issues</span>
          </div>
        </div>
      </div>
    </div>
  );
};
