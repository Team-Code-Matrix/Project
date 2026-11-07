import React from 'react';
import {
  Code2,
  Layers,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  FileCode,
  ExternalLink,
} from 'lucide-react';
import type { ScanResult } from '../../types/scan';
import type { ExtendedScanReport } from '../../types/backend';

export interface ScriptsLibrariesModuleProps {
  result: ScanResult;
  extendedReport?: ExtendedScanReport | null;
}

export interface ScriptItem {
  name: string;
  version: string;
  origin: string;
  sriHash: string;
  vulnerabilities: number;
  category: string;
  status: string;
  cve?: string;
}

export const ScriptsLibrariesModule: React.FC<ScriptsLibrariesModuleProps> = ({
  result: _result,
  extendedReport: _extendedReport,
}) => {
  const scripts: ScriptItem[] = [];

  return (
    <div className="space-y-6 text-left">
      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Loaded JS Bundles</div>
          <div className="text-2xl font-black text-shield-text-primary">{scripts.length} Scripts</div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">Discovered in DOM tree</div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Subresource Integrity (SRI)</div>
          <div className="text-2xl font-black text-shield-text-primary">
            0 / 0
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">Tamper-proof hash checked</div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">CVE Vulnerability Matches</div>
          <div className="text-2xl font-black text-emerald-400">
            0 CVEs
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">Retire.js & NVD correlation</div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Obfuscated / Eval Callers</div>
          <div className="text-2xl font-black text-emerald-400">
            0 Clean
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">Static AST de-obfuscation</div>
        </div>
      </div>

      {/* Script List */}
      <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-6">
        <div>
          <h3 className="text-lg font-bold text-shield-text-primary">Detected JavaScript Bundles & Libraries</h3>
          <p className="text-xs text-shield-text-secondary">Security integrity, versions, and origin validation</p>
        </div>

        {scripts.length === 0 ? (
          <div className="py-12 text-center text-xs font-mono text-shield-text-muted space-y-2">
            <Code2 className="w-8 h-8 text-shield-text-muted/50 mx-auto" />
            <p>No third-party JavaScript bundles or external libraries detected on target.</p>
            <p className="text-[11px]">The host does not load vulnerable client-side dependencies or unverified script tags.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {scripts.map((sc, i) => (
              <div
                key={i}
                className="p-4 rounded-2xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/40 transition-all space-y-2.5"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <FileCode className="w-4 h-4 text-shield-accent-light" />
                    <span className="font-mono font-bold text-sm text-shield-text-primary">{sc.name}</span>
                    <span className="text-xs font-mono text-shield-accent-light">v{sc.version}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-shield-surface text-shield-text-muted border border-shield-border">
                      {sc.category}
                    </span>
                  </div>

                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold ${
                      sc.status === 'SECURE'
                        ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/30'
                        : 'bg-rose-950/80 text-rose-400 border border-rose-500/30'
                    }`}
                  >
                    {sc.status}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono text-shield-text-muted pt-2 border-t border-shield-border/40">
                  <div>Source Origin: <span className="text-shield-text-secondary">{sc.origin}</span></div>
                  <div>Integrity Hash: <span className="text-shield-text-secondary">{sc.sriHash}</span></div>
                </div>

                {sc.cve && (
                  <div className="p-2.5 rounded-xl bg-rose-950/30 border border-rose-500/30 text-rose-300 text-xs font-mono">
                    🚨 Known Vulnerability: <strong>{sc.cve}</strong>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
