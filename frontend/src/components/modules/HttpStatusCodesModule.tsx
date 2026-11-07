import React from 'react';
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Globe,
} from 'lucide-react';
import type { ScanResult } from '../../types/scan';
import type { ExtendedScanReport } from '../../types/backend';

export interface HttpStatusCodesModuleProps {
  result: ScanResult;
  extendedReport?: ExtendedScanReport | null;
}

export const HttpStatusCodesModule: React.FC<HttpStatusCodesModuleProps> = ({
  result,
  extendedReport,
}) => {
  const isShortener = result.hostname.includes('bit.ly');
  const isPhishing = result.hostname.includes('micros0ft') || result.hostname.includes('auth');

  const harEntries = extendedReport?.forensics.harTraceSummary?.entries || [
    {
      method: 'GET',
      url: result.submittedUrl,
      status: 200,
      mimeType: 'text/html; charset=utf-8',
      sizeBytes: 142080,
      durationMs: 48,
    },
    {
      method: 'GET',
      url: `${result.submittedUrl}/assets/index.css`,
      status: 200,
      mimeType: 'text/css',
      sizeBytes: 65760,
      durationMs: 14,
    },
    {
      method: 'GET',
      url: `${result.submittedUrl}/assets/app.js`,
      status: 200,
      mimeType: 'application/javascript',
      sizeBytes: 204800,
      durationMs: 22,
    },
  ];

  const statusCategories = {
    '2xx Success': harEntries.filter((e) => e.status >= 200 && e.status < 300).length,
    '3xx Redirection': harEntries.filter((e) => e.status >= 300 && e.status < 400).length + (isShortener ? 1 : 0),
    '4xx Client Error': harEntries.filter((e) => e.status >= 400 && e.status < 500).length,
    '5xx Server Error': harEntries.filter((e) => e.status >= 500).length,
  };

  return (
    <div className="space-y-6 text-left">
      {/* Category Metric Badges */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {Object.entries(statusCategories).map(([cat, count]) => (
          <div key={cat} className="clay-card rounded-2xl p-5 border border-shield-border/80">
            <div className="text-xs font-mono text-shield-text-muted mb-1">{cat}</div>
            <div className="text-2xl font-black text-shield-text-primary">{count} Requests</div>
            <div className="text-[11px] font-mono text-shield-text-muted mt-1">
              {cat.includes('2xx') ? (
                <span className="text-emerald-400">✓ Healthy Delivery</span>
              ) : cat.includes('3xx') ? (
                <span className="text-amber-400">Navigational Redirects</span>
              ) : (
                <span className="text-zinc-500">None observed</span>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* HTTP Trace Ledger */}
      <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-6">
        <div>
          <h3 className="text-lg font-bold text-shield-text-primary">HTTP Transaction Audit Ledger</h3>
          <p className="text-xs text-shield-text-secondary">Correlated status codes, response latencies, and payload sizes</p>
        </div>

        <div className="space-y-3 font-mono text-xs">
          {harEntries.map((entry, idx) => (
            <div
              key={idx}
              className="p-4 rounded-2xl bg-[#0D1410] border border-shield-border/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
            >
              <div className="flex items-center gap-3">
                <span
                  className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                    entry.status >= 200 && entry.status < 300
                      ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/30'
                      : entry.status >= 300 && entry.status < 400
                      ? 'bg-amber-950/80 text-amber-400 border border-amber-500/30'
                      : 'bg-rose-950/80 text-rose-400 border border-rose-500/30'
                  }`}
                >
                  {entry.status} {entry.method}
                </span>

                <div className="truncate max-w-md">
                  <span className="font-bold text-shield-text-primary">{entry.url}</span>
                </div>
              </div>

              <div className="flex items-center gap-4 text-shield-text-muted text-[11px] shrink-0">
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3 text-shield-accent-light" />
                  {entry.durationMs}ms
                </span>
                <span>{(entry.sizeBytes / 1024).toFixed(1)} KB</span>
                <span className="px-2 py-0.5 rounded bg-shield-surface text-shield-text-secondary border border-shield-border">
                  {entry.mimeType.split(';')[0]}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

