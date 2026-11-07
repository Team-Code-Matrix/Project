import React, { useState } from 'react';
import type { WebSecurityAudit as WebSecType } from '../../types/backend';
import {
  FileCheck2,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Cookie,
  Globe2,
  Terminal,
  Fingerprint,
  Bug,
} from 'lucide-react';

interface WebSecurityAuditProps {
  webSec: WebSecType;
}

export const WebSecurityAudit: React.FC<WebSecurityAuditProps> = ({ webSec }) => {
  const [activeTab, setActiveTab] = useState<'headers' | 'cookies_cors' | 'tls_ja4' | 'exposure'>('headers');

  return (
    <div className="clay-card rounded-3xl p-6 md:p-8 space-y-6 text-left border border-shield-border/80">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-shield-border/60">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-shield-accent/20 border border-shield-accent/30 text-shield-accent-light">
            <FileCheck2 className="w-5 h-5 text-shield-accent-light" />
          </div>
          <div>
            <h2 className="text-xl md:text-2xl font-bold text-shield-text-primary">
              Application-Level Web Security Audit
            </h2>
            <p className="text-xs text-shield-text-secondary mt-0.5">
              Defensive HTTP headers, cookie isolation, CORS reflection, JA4+ TLS fingerprinting & passive exposure
            </p>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex flex-wrap items-center gap-1.5 p-1 rounded-xl bg-shield-surface-elevated border border-shield-border text-xs font-mono">
          <button
            type="button"
            onClick={() => setActiveTab('headers')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
              activeTab === 'headers'
                ? 'bg-shield-accent text-white font-semibold'
                : 'text-shield-text-secondary hover:text-shield-text-primary'
            }`}
          >
            HTTP Headers
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('cookies_cors')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
              activeTab === 'cookies_cors'
                ? 'bg-shield-accent text-white font-semibold'
                : 'text-shield-text-secondary hover:text-shield-text-primary'
            }`}
          >
            Cookies & CORS
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('tls_ja4')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
              activeTab === 'tls_ja4'
                ? 'bg-shield-accent text-white font-semibold'
                : 'text-shield-text-secondary hover:text-shield-text-primary'
            }`}
          >
            TLS & JA4+ Fingerprint
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('exposure')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
              activeTab === 'exposure'
                ? 'bg-shield-accent text-white font-semibold'
                : 'text-shield-text-secondary hover:text-shield-text-primary'
            }`}
          >
            Exposure & CVEs ({webSec.passiveExposure.matchedCves.length})
          </button>
        </div>
      </div>

      {/* AiTM Reverse Proxy Alert Callout if detected */}
      {webSec.tlsFingerprints.aitmProxySignatureDetected && (
        <div className="p-4 rounded-2xl bg-rose-950/25 border border-rose-500/40 text-rose-200 text-xs md:text-sm flex items-start gap-3.5 shadow-clay-card animate-fadeIn">
          <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <div className="font-bold uppercase tracking-wider mb-1 flex items-center gap-2 text-rose-300">
              <span>Adversary-in-the-Middle (AiTM) Reverse Proxy Signature Flagged</span>
              <span className="text-[10px] bg-rose-950/60 px-2 py-0.5 rounded font-mono border border-rose-500/40">
                CRITICAL THREAT
              </span>
            </div>
            <p className="text-rose-200 leading-relaxed">
              Server JA3S / JA4+ TLS fingerprint matches known AiTM toolkits (e.g., Evilginx2). Target acts as a transparent proxy to steal session cookies and bypass Multi-Factor Authentication.
            </p>
          </div>
        </div>
      )}

      {/* TAB 1: HTTP HEADERS */}
      {activeTab === 'headers' && (
        <div className="space-y-4 animate-fadeIn font-mono text-xs">
          <div className="p-5 rounded-2xl bg-[#090E0C] border border-shield-border/80 space-y-4">
            <div className="text-shield-text-primary font-bold text-sm border-b border-shield-border/40 pb-2 flex justify-between">
              <span>OWASP Defensive Response Headers Baseline</span>
              <span className="text-shield-accent-light">Grade: {webSec.httpHeaders.csp.grade}</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-shield-text-secondary">
              {/* CSP Card */}
              <div className="p-3.5 rounded-xl bg-shield-surface border border-shield-border/50 space-y-1.5">
                <div className="flex justify-between items-center">
                  <span className="font-bold text-shield-text-primary">Content-Security-Policy</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${webSec.httpHeaders.csp.present ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-300'}`}>
                    {webSec.httpHeaders.csp.present ? 'PRESENT' : 'MISSING'}
                  </span>
                </div>
                <div className="text-[11px] text-shield-text-muted">
                  {webSec.httpHeaders.csp.unsafeInline && <span className="text-shield-danger block">⚠ Allows 'unsafe-inline'</span>}
                  {webSec.httpHeaders.csp.unsafeEval && <span className="text-shield-warning block">⚠ Allows 'unsafe-eval'</span>}
                  {webSec.httpHeaders.csp.wildcardOrigins && <span className="text-shield-danger block">⚠ Wildcard origin '*' detected</span>}
                  {!webSec.httpHeaders.csp.unsafeInline && !webSec.httpHeaders.csp.unsafeEval && 'Strict policy with nonce / sha256 protection.'}
                </div>
              </div>

              {/* HSTS Card */}
              <div className="p-3.5 rounded-xl bg-shield-surface border border-shield-border/50 space-y-1.5">
                <div className="flex justify-between items-center">
                  <span className="font-bold text-shield-text-primary">Strict-Transport-Security</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${webSec.httpHeaders.hsts.present ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-300'}`}>
                    {webSec.httpHeaders.hsts.present ? `${webSec.httpHeaders.hsts.grade}` : 'MISSING'}
                  </span>
                </div>
                <div className="text-[11px] text-shield-text-muted">
                  Max-Age: {webSec.httpHeaders.hsts.maxAgeSeconds}s ({Math.round(webSec.httpHeaders.hsts.maxAgeSeconds / 86400)} days)
                  {webSec.httpHeaders.hsts.preloaded && <span className="text-shield-success block">✓ Registered in Chromium Preload List</span>}
                  {webSec.httpHeaders.hsts.includeSubdomains && <span className="text-shield-success block">✓ Includes Subdomains</span>}
                </div>
              </div>

              {/* XFO Card */}
              <div className="p-3.5 rounded-xl bg-shield-surface border border-shield-border/50 space-y-1.5">
                <div className="flex justify-between items-center">
                  <span className="font-bold text-shield-text-primary">X-Frame-Options (Clickjacking)</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${webSec.httpHeaders.xFrameOptions !== 'MISSING' ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-300'}`}>
                    {webSec.httpHeaders.xFrameOptions}
                  </span>
                </div>
                <div className="text-[11px] text-shield-text-muted">
                  {webSec.httpHeaders.xFrameOptions === 'DENY'
                    ? 'Page cannot be displayed in iframe or frame.'
                    : webSec.httpHeaders.xFrameOptions === 'SAMEORIGIN'
                    ? 'Frame display restricted to same origin.'
                    : 'Missing frame protection; vulnerable to UI redressing.'}
                </div>
              </div>

              {/* Nosniff Card */}
              <div className="p-3.5 rounded-xl bg-shield-surface border border-shield-border/50 space-y-1.5">
                <div className="flex justify-between items-center">
                  <span className="font-bold text-shield-text-primary">X-Content-Type-Options</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${webSec.httpHeaders.xContentTypeOptionsNosniff ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-300'}`}>
                    {webSec.httpHeaders.xContentTypeOptionsNosniff ? 'NOSNIFF' : 'MISSING'}
                  </span>
                </div>
                <div className="text-[11px] text-shield-text-muted">
                  {webSec.httpHeaders.xContentTypeOptionsNosniff
                    ? 'Prevents MIME-type sniffing of executable files.'
                    : 'Browser may guess MIME type; vulnerable to script injection.'}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: COOKIES & CORS */}
      {activeTab === 'cookies_cors' && (
        <div className="space-y-4 animate-fadeIn font-mono text-xs">
          <div className="p-5 rounded-2xl bg-[#090E0C] border border-shield-border/80 space-y-4">
            <div className="text-shield-text-primary font-bold text-sm border-b border-shield-border/40 pb-2">
              Session Cookie Flags & CORS Inspection
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-shield-surface border border-shield-border/50 space-y-2">
                <div className="font-bold text-shield-text-primary flex items-center gap-1.5">
                  <Cookie className="w-4 h-4 text-shield-accent-light" />
                  <span>Cookie Security Analysis</span>
                </div>
                <div className="text-shield-text-secondary space-y-1">
                  <div>Total Cookies Audited: {webSec.cookieSecurity.totalCookiesCount}</div>
                  <div>Missing Secure Flag: <span className={webSec.cookieSecurity.secureFlagsMissingCount > 0 ? 'text-shield-danger font-bold' : 'text-shield-success'}>{webSec.cookieSecurity.secureFlagsMissingCount}</span></div>
                  <div>Missing HttpOnly Flag: <span className={webSec.cookieSecurity.httpOnlyMissingCount > 0 ? 'text-shield-danger font-bold' : 'text-shield-success'}>{webSec.cookieSecurity.httpOnlyMissingCount}</span></div>
                  <div>Missing SameSite Flag: <span className={webSec.cookieSecurity.sameSiteMissingCount > 0 ? 'text-shield-warning font-bold' : 'text-shield-success'}>{webSec.cookieSecurity.sameSiteMissingCount}</span></div>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-shield-surface border border-shield-border/50 space-y-2">
                <div className="font-bold text-shield-text-primary flex items-center gap-1.5">
                  <Globe2 className="w-4 h-4 text-shield-accent-light" />
                  <span>CORS Cross-Origin Policy</span>
                </div>
                <div className="text-shield-text-secondary space-y-1">
                  <div>Policy Status: <span className="font-bold text-shield-accent-light">{webSec.corsPolicy.verdict}</span></div>
                  <div>Wildcard Origin (*): <span className={webSec.corsPolicy.wildcardOrigin ? 'text-shield-danger font-bold' : 'text-shield-success'}>{webSec.corsPolicy.wildcardOrigin ? 'YES (Exposed)' : 'NO'}</span></div>
                  <div>Origin Header Reflection: <span className={webSec.corsPolicy.originReflection ? 'text-shield-danger font-bold' : 'text-shield-success'}>{webSec.corsPolicy.originReflection ? 'YES (Vulnerable)' : 'NO'}</span></div>
                  <div>Credentials Allowed: <span>{webSec.corsPolicy.credentialsAllowed ? 'true' : 'false'}</span></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: TLS & JA4+ FINGERPRINTING */}
      {activeTab === 'tls_ja4' && (
        <div className="space-y-4 animate-fadeIn font-mono text-xs">
          <div className="p-5 rounded-2xl bg-[#090E0C] border border-shield-border/80 space-y-4">
            <div className="text-shield-text-primary font-bold text-sm border-b border-shield-border/40 pb-2 flex justify-between">
              <span>TLS Cipher Suite & Server Fingerprinting</span>
              <span className="text-shield-accent-light">{webSec.tlsFingerprints.negotiatedProtocol}</span>
            </div>

            <div className="space-y-2.5 text-shield-text-secondary">
              <div className="p-3 rounded-xl bg-shield-surface border border-shield-border/50">
                <span className="text-shield-text-muted">Negotiated Cipher:</span>{' '}
                <span className="text-shield-text-primary font-bold">{webSec.tlsFingerprints.negotiatedCipher}</span>
                <div className="mt-1 flex gap-3 text-[11px]">
                  <span className={webSec.tlsFingerprints.forwardSecrecy ? 'text-shield-success' : 'text-shield-danger'}>
                    {webSec.tlsFingerprints.forwardSecrecy ? '✓ Perfect Forward Secrecy (PFS)' : '✗ No Forward Secrecy'}
                  </span>
                  <span className={webSec.tlsFingerprints.weakCipherDetected ? 'text-shield-danger font-bold' : 'text-shield-success'}>
                    {webSec.tlsFingerprints.weakCipherDetected ? '⚠ Weak / Deprecated Cipher' : '✓ Strong Cipher'}
                  </span>
                </div>
              </div>

              {/* JA3S and JA4+ Hashes */}
              <div className="p-3 rounded-xl bg-shield-surface border border-shield-border/50 space-y-1.5">
                <div className="flex items-center gap-1.5 font-bold text-shield-text-primary">
                  <Fingerprint className="w-4 h-4 text-shield-accent-light" />
                  <span>Server JA3S & JA4+ TLS Fingerprints</span>
                </div>
                {webSec.tlsFingerprints.ja4sHash && (
                  <div>
                    <span className="text-shield-text-muted">JA4S Hash:</span>{' '}
                    <span className="text-shield-accent-light select-all">{webSec.tlsFingerprints.ja4sHash}</span>
                  </div>
                )}
                {webSec.tlsFingerprints.ja3sHash && (
                  <div>
                    <span className="text-shield-text-muted">JA3S Hash:</span>{' '}
                    <span className="text-shield-accent-light select-all">{webSec.tlsFingerprints.ja3sHash}</span>
                  </div>
                )}
                <p className="text-[11px] text-shield-text-muted mt-1">
                  Used by network defenders to fingerprint backend web servers regardless of domain hopping.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: PASSIVE EXPOSURE & CVE MATCHES */}
      {activeTab === 'exposure' && (
        <div className="space-y-4 animate-fadeIn font-mono text-xs">
          <div className="p-5 rounded-2xl bg-[#090E0C] border border-shield-border/80 space-y-4">
            <div className="text-shield-text-primary font-bold text-sm border-b border-shield-border/40 pb-2 flex justify-between">
              <span>Passive Banner Exposure & Software Vulnerabilities (CVEs)</span>
              <span className="text-shield-danger">{webSec.passiveExposure.matchedCves.length} CVEs Detected</span>
            </div>

            {/* Banners & Exposed Files */}
            <div className="p-3 rounded-xl bg-shield-surface border border-shield-border/50 space-y-1 text-shield-text-secondary">
              <div><span className="text-shield-text-muted">Server Banner:</span> {webSec.passiveExposure.serverBanner || 'Hidden (Standard)'}</div>
              <div><span className="text-shield-text-muted">X-Powered-By:</span> {webSec.passiveExposure.xPoweredBy || 'None (Suppressed)'}</div>
              <div>
                <span className="text-shield-text-muted">Exposed Sensitive Files:</span>{' '}
                {webSec.passiveExposure.exposedFilesObserved.length > 0 ? (
                  <span className="text-shield-danger font-bold">{webSec.passiveExposure.exposedFilesObserved.join(', ')}</span>
                ) : (
                  <span className="text-shield-success">None observed</span>
                )}
              </div>
            </div>

            {/* CVEs List */}
            {webSec.passiveExposure.matchedCves.length > 0 ? (
              <div className="space-y-2">
                {webSec.passiveExposure.matchedCves.map((cve) => (
                  <div key={cve.cveId} className="p-3 rounded-xl bg-rose-950/20 border border-rose-500/30 flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <Bug className="w-3.5 h-3.5 text-rose-400" />
                        <span className="font-bold text-rose-300">{cve.cveId}</span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-rose-950 text-rose-300 border border-rose-500/40">
                          {cve.severity}
                        </span>
                        <span className="text-shield-text-muted text-[11px]">{cve.component}</span>
                      </div>
                      <p className="text-shield-text-secondary text-[11px] mt-1 leading-relaxed">
                        {cve.summary}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-4 text-shield-text-muted">
                No known high or critical CVE advisories mapped to observed server components.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

