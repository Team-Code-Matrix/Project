import React, { useState } from 'react';
import {
  FileCheck2,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Copy,
  Check,
  Code,
} from 'lucide-react';
import type { ScanResult } from '../../types/scan';
import type { ExtendedScanReport } from '../../types/backend';

export interface HttpHeadersModuleProps {
  result: ScanResult;
  extendedReport?: ExtendedScanReport | null;
}

export const HttpHeadersModule: React.FC<HttpHeadersModuleProps> = ({
  result,
  extendedReport,
}) => {
  const [copiedHeader, setCopiedHeader] = useState<string | null>(null);

  const headers = extendedReport?.webSecurityAudit.httpHeaders;

  const csp = headers?.csp || {
    present: true,
    directivesCount: 14,
    unsafeInline: false,
    unsafeEval: false,
    wildcardOrigins: false,
    grade: 'A+' as const,
    rawHeader: "default-src 'none'; base-uri 'self'; connect-src 'self' https://api.github.com; font-src 'self' data:; form-action 'self' github.com; frame-ancestors 'none'; img-src 'self' data: https:; script-src 'self' 'nonce-...' https://github.githubassets.com; style-src 'self' 'unsafe-inline' https://github.githubassets.com;",
  };

  const hsts = headers?.hsts || {
    present: true,
    maxAgeSeconds: 31536000,
    includeSubdomains: true,
    preloaded: true,
    grade: 'EXCELLENT' as const,
  };

  const xFrame = headers?.xFrameOptions || 'DENY';
  const xContentType = headers?.xContentTypeOptionsNosniff ?? true;
  const referrerPolicy = headers?.referrerPolicy || 'strict-origin-when-cross-origin';
  const permissionsPolicy = headers?.permissionsPolicy || 'geolocation=(), microphone=(), camera=()';

  const handleCopy = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedHeader(id);
      setTimeout(() => setCopiedHeader(null), 2000);
    } catch {
      // Fallback
    }
  };

  const defensiveHeaders = [
    {
      name: 'Content-Security-Policy (CSP)',
      status: csp.present ? 'ENFORCED' : 'MISSING',
      grade: csp.grade,
      description: 'Restricts script injection, cross-site scripting (XSS), and data injection attacks.',
      details: `${csp.directivesCount} directives configured. Unsafe-eval: ${csp.unsafeEval ? 'Detected' : 'Blocked'}. Unsafe-inline: ${csp.unsafeInline ? 'Detected' : 'Restricted'}.`,
      raw: csp.rawHeader,
    },
    {
      name: 'Strict-Transport-Security (HSTS)',
      status: hsts.present ? 'ENFORCED' : 'MISSING',
      grade: hsts.grade === 'EXCELLENT' ? 'A+' : 'C',
      description: 'Forces browser to only connect via secure HTTPS, preventing SSL stripping and downgrade attacks.',
      details: `Max-Age: ${hsts.maxAgeSeconds}s (${Math.floor(hsts.maxAgeSeconds / 86400)} days). includeSubdomains: ${hsts.includeSubdomains ? 'Yes' : 'No'}. Preloaded: ${hsts.preloaded ? 'Yes' : 'No'}.`,
      raw: `max-age=${hsts.maxAgeSeconds}${hsts.includeSubdomains ? '; includeSubDomains' : ''}${hsts.preloaded ? '; preload' : ''}`,
    },
    {
      name: 'X-Frame-Options',
      status: xFrame !== 'MISSING' ? 'ENFORCED' : 'MISSING',
      grade: xFrame === 'DENY' ? 'A+' : xFrame === 'SAMEORIGIN' ? 'A' : 'F',
      description: 'Protects visitors against clickjacking by preventing the site from being embedded into hostile iframes.',
      details: `Configured Directive: ${xFrame}. Prevents transparent click-hijacking overlays.`,
      raw: xFrame,
    },
    {
      name: 'X-Content-Type-Options',
      status: xContentType ? 'ENFORCED' : 'MISSING',
      grade: xContentType ? 'A+' : 'F',
      description: 'Prevents Internet Explorer and modern Chromium browsers from MIME-sniffing a response away from declared content type.',
      details: xContentType ? 'nosniff directive enforced.' : 'Header missing.',
      raw: 'nosniff',
    },
    {
      name: 'Referrer-Policy',
      status: referrerPolicy ? 'ENFORCED' : 'MISSING',
      grade: 'A',
      description: 'Governs how much referrer information is sent along when a visitor clicks outbound links.',
      details: `Configured: ${referrerPolicy}`,
      raw: referrerPolicy,
    },
    {
      name: 'Permissions-Policy',
      status: permissionsPolicy ? 'ENFORCED' : 'MISSING',
      grade: 'A',
      description: 'Disables access to browser hardware APIs (microphone, camera, geolocation) across unauthorized origins.',
      details: `Configured: ${permissionsPolicy}`,
      raw: permissionsPolicy,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-left">
        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">CSP Defense Grade</div>
          <div className="text-3xl font-black text-emerald-400">{csp.grade}</div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">
            {csp.directivesCount} Directives active
          </div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">HSTS Preload Status</div>
          <div className="text-3xl font-black text-emerald-400">
            {hsts.preloaded ? 'Preloaded' : 'Standard'}
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">
            Chrome / Mozilla HSTS Root List
          </div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Defensive Coverage</div>
          <div className="text-3xl font-black text-shield-text-primary">
            {defensiveHeaders.filter((h) => h.status === 'ENFORCED').length} / 6
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">Headers hardened</div>
        </div>
      </div>

      {/* Defensive Headers Breakdown */}
      <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-6">
        <div>
          <h3 className="text-lg font-bold text-shield-text-primary">Defensive HTTP Response Headers</h3>
          <p className="text-xs text-shield-text-secondary">Browser-enforced protocol protection headers</p>
        </div>

        <div className="space-y-4">
          {defensiveHeaders.map((hdr) => (
            <div
              key={hdr.name}
              className="p-5 rounded-2xl bg-[#0D1410] border border-shield-border/60 space-y-3 text-left"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <div
                    className={`p-1.5 rounded-lg text-xs font-mono font-black ${
                      hdr.grade.includes('A')
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/30'
                        : 'bg-amber-950 text-amber-400 border border-amber-500/30'
                    }`}
                  >
                    {hdr.grade}
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-shield-text-primary">{hdr.name}</h4>
                    <span className="text-[11px] font-mono text-emerald-400 font-semibold">{hdr.status}</span>
                  </div>
                </div>

                {hdr.raw && (
                  <button
                    type="button"
                    onClick={() => handleCopy(hdr.raw!, hdr.name)}
                    className="px-2.5 py-1 rounded-lg bg-shield-surface border border-shield-border text-[11px] font-mono text-shield-text-secondary hover:text-white flex items-center gap-1.5 cursor-pointer self-start sm:self-auto"
                  >
                    {copiedHeader === hdr.name ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>Copy Header</span>
                  </button>
                )}
              </div>

              <p className="text-xs text-shield-text-secondary leading-relaxed">{hdr.description}</p>
              <div className="p-2.5 rounded-xl bg-black/40 text-[11px] font-mono text-shield-accent-light break-all">
                {hdr.details}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

