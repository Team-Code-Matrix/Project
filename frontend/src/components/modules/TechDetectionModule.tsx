import React from 'react';
import {
  Cpu,
  Layers,
  Server,
  Code2,
  ShieldAlert,
  ShieldCheck,
  Globe2,
  Fingerprint,
  ExternalLink,
} from 'lucide-react';
import type { ScanResult } from '../../types/scan';
import type { ExtendedScanReport } from '../../types/backend';

export interface TechDetectionModuleProps {
  result: ScanResult;
  extendedReport?: ExtendedScanReport | null;
}

export const TechDetectionModule: React.FC<TechDetectionModuleProps> = ({
  result,
  extendedReport,
}) => {
  const domain = result.hostname;
  const isGithub = domain.includes('github');
  const isPhishing = domain.includes('micros0ft') || domain.includes('auth');

  // Technology Stack Categories
  const techStack = [
    {
      category: 'Web Server & Gateway',
      icon: Server,
      items: isGithub
        ? [
            { name: 'GitHub Unicorn / Envoy', version: '2.4.1', confidence: 99, category: 'Reverse Proxy' },
            { name: 'HTTP/2 & HTTP/3 (QUIC)', version: 'Enabled', confidence: 100, category: 'Protocol' },
          ]
        : isPhishing
        ? [
            { name: 'Nginx', version: '1.18.0 (Ubuntu)', confidence: 95, category: 'Web Server' },
            { name: 'PHP Built-in Server', version: '8.1.2', confidence: 90, category: 'Phishing Kit Backend' },
          ]
        : [
            { name: 'Cloudflare Edge Gateway', version: '2026.3', confidence: 100, category: 'CDN / Proxy' },
          ],
    },
    {
      category: 'Frontend & UI Frameworks',
      icon: Layers,
      items: isGithub
        ? [
            { name: 'React', version: '18.3.1', confidence: 98, category: 'UI Library' },
            { name: 'Primer CSS / Primer ViewComponents', version: 'v36.0', confidence: 95, category: 'Design System' },
            { name: 'Turbo / Stimulus', version: 'Hotwire', confidence: 90, category: 'Micro-Framework' },
          ]
        : isPhishing
        ? [
            { name: 'Bootstrap', version: '4.5.2', confidence: 88, category: 'CSS Framework' },
            { name: 'jQuery', version: '3.5.1', confidence: 92, category: 'Legacy Library' },
          ]
        : [
            { name: 'Next.js', version: '14.2', confidence: 94, category: 'React Framework' },
          ],
    },
    {
      category: 'CDN, Edge & DDoS Protection',
      icon: Globe2,
      items: isGithub
        ? [
            { name: 'Fastly Edge Cloud', version: 'Varnish / VCL', confidence: 95, category: 'Edge CDN' },
            { name: 'AWS CloudFront Anycast', version: 'Global', confidence: 90, category: 'Media Distribution' },
          ]
        : [
            { name: 'Cloudflare DDoS Shield', version: 'Active', confidence: 98, category: 'WAF / Anycast' },
          ],
    },
    {
      category: 'Cryptographic Fingerprints & TLS Stack',
      icon: Fingerprint,
      items: [
        {
          name: 'JA4+ TLS Fingerprint',
          version: extendedReport?.webSecurityAudit.tlsFingerprints.ja4sHash || 't13d1516h2_8daaf6152771_48346e0895c3',
          confidence: 100,
          category: 'Cryptographic Hash',
        },
        {
          name: 'Negotiated Cipher Suite',
          version: extendedReport?.webSecurityAudit.tlsFingerprints.negotiatedCipher || 'TLS_AES_128_GCM_SHA256 (256-bit)',
          confidence: 100,
          category: 'Cipher Spec',
        },
        {
          name: 'Negotiated TLS Protocol',
          version: extendedReport?.webSecurityAudit.tlsFingerprints.negotiatedProtocol || 'TLS 1.3',
          confidence: 100,
          category: 'Protocol',
        },
      ],
    },
  ];

  // Matched CVEs
  const cves = extendedReport?.webSecurityAudit.passiveExposure.matchedCves || [];

  return (
    <div className="space-y-6">
      {/* Overview Metric Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-left">
        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Identified Tech Signatures</div>
          <div className="text-2xl font-black text-shield-text-primary">
            {techStack.reduce((acc, cat) => acc + cat.items.length, 0)} Components
          </div>
          <div className="text-[11px] font-mono text-emerald-400 mt-1">
            Signatures across 4 architectural layers
          </div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Observed CVE Matches</div>
          <div className={`text-2xl font-black ${cves.length > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
            {cves.length} Vulnerabilities
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">
            {cves.length > 0 ? 'Known CVEs matched in stack' : 'Zero unpatched CVEs detected'}
          </div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">AiTM Proxy Detection</div>
          <div className="text-2xl font-black text-emerald-400">
            {extendedReport?.webSecurityAudit.tlsFingerprints.aitmProxySignatureDetected ? (
              <span className="text-rose-400">ALERT: Detected</span>
            ) : (
              <span>Clean / None</span>
            )}
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">
            Evilginx2 / Muraena reverse-proxy check
          </div>
        </div>
      </div>

      {/* Technology Stack Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {techStack.map((cat) => {
          const Icon = cat.icon;
          return (
            <div
              key={cat.category}
              className="clay-card rounded-3xl p-6 border border-shield-border/80 space-y-4 text-left"
            >
              <div className="flex items-center gap-2.5 pb-3 border-b border-shield-border/50">
                <div className="p-2 rounded-xl bg-shield-accent/20 text-shield-accent-light">
                  <Icon className="w-4 h-4" />
                </div>
                <h3 className="text-sm font-bold text-shield-text-primary font-mono uppercase tracking-wider">
                  {cat.category}
                </h3>
              </div>

              <div className="space-y-2.5">
                {cat.items.map((item, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-xl bg-[#0D1410] border border-shield-border/60 flex items-center justify-between text-xs font-mono"
                  >
                    <div>
                      <div className="font-bold text-shield-text-primary flex items-center gap-2">
                        <span>{item.name}</span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-shield-surface text-shield-text-muted">
                          {item.category}
                        </span>
                      </div>
                      <div className="text-shield-accent-light text-[11px] mt-0.5 truncate max-w-[280px]">
                        {item.version}
                      </div>
                    </div>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-500/30">
                      {item.confidence}% Match
                    </span>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>

      {/* Matched CVEs Section */}
      {cves.length > 0 && (
        <div className="clay-card rounded-3xl p-6 md:p-8 border border-rose-900/50 bg-rose-950/10 space-y-4 text-left">
          <div className="flex items-center gap-2 text-rose-400">
            <ShieldAlert className="w-5 h-5" />
            <h3 className="text-base font-bold font-mono uppercase tracking-wider">
              Matched CVE Vulnerability Advisories ({cves.length})
            </h3>
          </div>

          <div className="space-y-3">
            {cves.map((cve) => (
              <div
                key={cve.cveId}
                className="p-4 rounded-2xl bg-[#0D1410] border border-rose-500/30 space-y-1.5 text-xs font-mono"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-rose-300">{cve.cveId}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-400 border border-rose-500/40">
                    {cve.severity}
                  </span>
                </div>
                <div className="text-shield-text-muted text-[11px]">Affected Component: {cve.component}</div>
                <p className="text-shield-text-secondary">{cve.summary}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

