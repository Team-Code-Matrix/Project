import React from 'react';
import {
  Files,
  Globe,
  FileCheck2,
  ExternalLink,
  Layers,
  CheckCircle2,
} from 'lucide-react';
import type { ScanResult } from '../../types/scan';
import type { ExtendedScanReport } from '../../types/backend';

export interface WebsitePagesModuleProps {
  result: ScanResult;
  extendedReport?: ExtendedScanReport | null;
}

export const WebsitePagesModule: React.FC<WebsitePagesModuleProps> = ({
  result,
  extendedReport,
}) => {
  const isGithub = result.hostname.includes('github');
  const isPhishing = result.hostname.includes('micros0ft') || result.hostname.includes('auth');

  const pages = isGithub
    ? [
        {
          url: 'https://github.com/',
          title: 'GitHub: Let’s build from here · GitHub',
          statusCode: 200,
          contentType: 'text/html; charset=utf-8',
          depth: 0,
          size: '248 KB',
        },
        {
          url: 'https://github.com/features',
          title: 'Features · GitHub',
          statusCode: 200,
          contentType: 'text/html; charset=utf-8',
          depth: 1,
          size: '184 KB',
        },
        {
          url: 'https://github.com/security',
          title: 'Security at GitHub · GitHub',
          statusCode: 200,
          contentType: 'text/html; charset=utf-8',
          depth: 1,
          size: '152 KB',
        },
        {
          url: 'https://github.com/login',
          title: 'Sign in to GitHub · GitHub',
          statusCode: 200,
          contentType: 'text/html; charset=utf-8',
          depth: 1,
          size: '98 KB',
        },
      ]
    : isPhishing
    ? [
        {
          url: result.submittedUrl,
          title: 'Sign in to your Microsoft Account (Fake Form)',
          statusCode: 200,
          contentType: 'text/html; charset=utf-8',
          depth: 0,
          size: '42 KB',
        },
      ]
    : [
        {
          url: result.submittedUrl,
          title: 'Homepage Landing Document',
          statusCode: 200,
          contentType: 'text/html; charset=utf-8',
          depth: 0,
          size: '64 KB',
        },
      ];

  return (
    <div className="space-y-6 text-left">
      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Discovered Pages</div>
          <div className="text-2xl font-black text-shield-text-primary">{pages.length} Pages</div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">Inspected in domain scope</div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Crawl Depth Scope</div>
          <div className="text-2xl font-black text-emerald-400">Depth 1 Traversal</div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">Non-destructive exploration</div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Average Page Size</div>
          <div className="text-2xl font-black text-shield-text-primary">145 KB</div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">Gzip / Brotli compressed</div>
        </div>
      </div>

      {/* Pages Table */}
      <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-6">
        <div>
          <h3 className="text-lg font-bold text-shield-text-primary">Discovered Site Page Map</h3>
          <p className="text-xs text-shield-text-secondary">Correlated HTML documents, page titles, and HTTP statuses</p>
        </div>

        <div className="space-y-4 font-mono text-xs">
          {pages.map((pg, i) => (
            <div
              key={i}
              className="p-4 rounded-2xl bg-[#0D1410] border border-shield-border/60 space-y-2.5"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 font-bold border border-emerald-500/30">
                    HTTP {pg.statusCode}
                  </span>
                  <span className="font-bold text-sm text-shield-text-primary truncate">{pg.title}</span>
                </div>
                <div className="flex items-center gap-2 text-shield-text-muted text-[11px]">
                  <span>Depth: {pg.depth}</span>
                  <span>•</span>
                  <span>{pg.size}</span>
                </div>
              </div>

              <div className="p-2 rounded-xl bg-black/40 text-shield-accent-light break-all">
                {pg.url}
              </div>

              <div className="text-[11px] text-shield-text-muted pt-1">
                Content-Type: <strong className="text-shield-text-secondary">{pg.contentType}</strong>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

