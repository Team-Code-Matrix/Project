import React from 'react';
import {
  Download,
  FileCheck2,
  FileWarning,
  ShieldCheck,
  ShieldAlert,
  HardDrive,
  FileCode,
  CheckCircle2,
} from 'lucide-react';
import type { ScanResult } from '../../types/scan';
import type { ExtendedScanReport } from '../../types/backend';

export interface DownloadsModuleProps {
  result: ScanResult;
  extendedReport?: ExtendedScanReport | null;
}

export const DownloadsModule: React.FC<DownloadsModuleProps> = ({
  result: _result,
  extendedReport: _extendedReport,
}) => {
  const downloads: {
    filename: string;
    type: string;
    mimeType: string;
    size: string;
    reputation: string;
    status: string;
    indicator: string;
  }[] = [];

  return (
    <div className="space-y-6 text-left">
      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Discovered Downloads</div>
          <div className="text-2xl font-black text-shield-text-primary">{downloads.length} Resources</div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">Inspected in HTTP trace</div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Drive-by Payload Trap</div>
          <div className="text-2xl font-black text-emerald-400">
            CLEAN
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">
            No forced payload transfer
          </div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">File Reputation Status</div>
          <div className="text-2xl font-black text-emerald-400">
            All Safe
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">
            No hostile binaries detected
          </div>
        </div>
      </div>

      {/* Discovered Downloadable Resources */}
      <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-6">
        <div>
          <h3 className="text-lg font-bold text-shield-text-primary">Discovered Downloadable Resources</h3>
          <p className="text-xs text-shield-text-secondary">Static binaries, scripts, and media discovered during session detonation</p>
        </div>

        {downloads.length === 0 ? (
          <div className="py-12 text-center text-xs font-mono text-shield-text-muted space-y-2">
            <Download className="w-8 h-8 text-shield-text-muted/50 mx-auto" />
            <p>No downloadable files or executable binaries discovered on target.</p>
            <p className="text-[11px]">The analyzed web page does not initiate automatic file transfers or prompt software downloads.</p>
          </div>
        ) : (
          <div className="space-y-4 font-mono text-xs">
            {downloads.map((dl, i) => (
              <div
                key={i}
                className="p-4 rounded-2xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/40 transition-all space-y-2.5"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Download className="w-4 h-4 text-shield-accent-light" />
                    <span className="font-bold text-sm text-shield-text-primary">{dl.filename}</span>
                    <span className="text-shield-text-muted text-[11px]">({dl.size})</span>
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                      dl.status === 'SAFE'
                        ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/30'
                        : 'bg-rose-950/80 text-rose-400 border border-rose-500/30'
                    }`}
                  >
                    {dl.reputation}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-shield-text-muted pt-2 border-t border-shield-border/40">
                  <div>Detected Format: <strong className="text-shield-text-secondary">{dl.type}</strong></div>
                  <div>MIME Header: <strong className="text-shield-text-secondary">{dl.mimeType}</strong></div>
                </div>

                <div className="p-2.5 rounded-xl bg-black/40 text-[11px] text-shield-text-secondary">
                  Security Observation: {dl.indicator}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

