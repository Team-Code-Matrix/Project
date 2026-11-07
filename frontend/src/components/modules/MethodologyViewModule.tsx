import React from 'react';
import {
  BookOpen,
  Layers,
  Scale,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  FileCheck2,
  Network,
  Cpu,
  Lock,
} from 'lucide-react';

export const MethodologyViewModule: React.FC = () => {
  const pillars = [
    {
      name: '1. Phishing & Impersonation Detection',
      weight: '25%',
      icon: ShieldAlert,
      description: 'MicroVM sandbox DOM detonation, computer vision brand similarity (pHash, dHash, MurmurHash3 favicon), YARA rule matching, anti-analysis evasion bypass, and password/payment input harvesting heuristics.',
    },
    {
      name: '2. Cryptographic TLS/PKI Validation',
      weight: '25%',
      icon: Lock,
      description: 'RFC 5280 multi-store path validation across Mozilla NSS, Google Chrome Root, Apple, and Microsoft trust stores. Verifies Certificate Transparency (CT) Merkle inclusion proofs, OCSP stapling, CRL health, key entropy, ROCA vulnerabilities, and DNS CAA authorization.',
    },
    {
      name: '3. Application-Level Web Security',
      weight: '15%',
      icon: FileCheck2,
      description: 'Evaluates defensive HTTP response headers (strict CSP, HSTS preload, X-Frame-Options, X-Content-Type-Options nosniff, Referrer-Policy), cookie isolation (Secure, HttpOnly, SameSite), JA4+ TLS client/server fingerprinting, and passive CVE exposure.',
    },
    {
      name: '4. Redirect Chain & Infrastructure Traversal',
      weight: '15%',
      icon: Network,
      description: 'Full unshortening traversal across HTTP 301/302, HTML Meta Refresh, and window.location scripts. Maps hop-by-hop destination IPs, Autonomous Systems (ASNs), and detects cloaking destination mismatches.',
    },
    {
      name: '5. Domain & URL Lexical Intelligence',
      weight: '10%',
      icon: Cpu,
      description: 'Shannon entropy calculation, Punycode homograph attack detection, sub-domain depth, suspicious TLD risk scoring, and RDAP/WHOIS domain tenure registration age auditing.',
    },
    {
      name: '6. Collaborative Threat Intelligence',
      weight: '10%',
      icon: Layers,
      description: 'Federated real-time correlation against Abuse.ch URLhaus, ThreatFox, MISP, STIX 2.1 indicators, and community incident reports with half-life confidence decay weighting.',
    },
  ];

  return (
    <div className="space-y-6 text-left">
      {/* Overview Banner */}
      <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-4">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-shield-surface border border-shield-border text-xs font-mono text-shield-accent-light">
          <BookOpen className="w-3.5 h-3.5" />
          <span>CYBER INTELLIGENCE SCORING SPECIFICATION</span>
        </div>
        <h2 className="text-xl md:text-2xl font-bold text-shield-text-primary">
          TrustShield Multi-Model Scoring Methodology
        </h2>
        <p className="text-sm text-shield-text-secondary leading-relaxed">
          TrustShield computes an explainable, deterministic Trust Score between 0 and 100 by aggregating weighted verdicts from six independent cybersecurity analysis engines. Confirmed critical vulnerabilities trigger safety overrides that supersede weighted averages.
        </p>
      </div>

      {/* 6 Pillars Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {pillars.map((pil) => {
          const Icon = pil.icon;
          return (
            <div
              key={pil.name}
              className="clay-card rounded-3xl p-6 border border-shield-border/80 space-y-3"
            >
              <div className="flex items-center justify-between pb-3 border-b border-shield-border/50">
                <div className="flex items-center gap-2">
                  <Icon className="w-4 h-4 text-shield-accent-light" />
                  <h3 className="font-bold text-sm text-shield-text-primary font-mono">{pil.name}</h3>
                </div>
                <span className="px-2 py-0.5 rounded-lg bg-emerald-950 text-emerald-400 font-bold text-xs font-mono border border-emerald-500/30">
                  Weight: {pil.weight}
                </span>
              </div>
              <p className="text-xs text-shield-text-secondary leading-relaxed">{pil.description}</p>
            </div>
          );
        })}
      </div>

      {/* Critical Overrides Explanation */}
      <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-4 bg-shield-surface/60">
        <div className="flex items-center gap-2 text-rose-400">
          <ShieldAlert className="w-5 h-5" />
          <h3 className="text-base font-bold font-mono uppercase tracking-wider">
            Deterministic Safety Overrides (Veto Triggers)
          </h3>
        </div>

        <p className="text-xs md:text-sm text-shield-text-secondary leading-relaxed">
          Regardless of high domain tenure or clean HTTP headers, the platform executes a hard score cap whenever fatal safety violations are identified:
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
          <div className="p-3.5 rounded-xl bg-[#0D1410] border border-shield-border/60">
            <span className="text-rose-400 font-bold">1. Confirmed Phishing Kit:</span>
            <p className="text-shield-text-muted mt-1 text-[11px]">Caps score at &le; 15/100 and enforces MALICIOUS verdict.</p>
          </div>
          <div className="p-3.5 rounded-xl bg-[#0D1410] border border-shield-border/60">
            <span className="text-purple-400 font-bold">2. Revoked / Rogue CA Certificate:</span>
            <p className="text-shield-text-muted mt-1 text-[11px]">Caps score at &le; 25/100 and flags PKI_TRUST_COMPROMISED.</p>
          </div>
          <div className="p-3.5 rounded-xl bg-[#0D1410] border border-shield-border/60">
            <span className="text-amber-400 font-bold">3. Multi-Hop Malicious Redirect:</span>
            <p className="text-shield-text-muted mt-1 text-[11px]">Caps score at &le; 40/100 when landing URL diverges from submitted target.</p>
          </div>
          <div className="p-3.5 rounded-xl bg-[#0D1410] border border-shield-border/60">
            <span className="text-yellow-400 font-bold">4. Expired TLS Certificate:</span>
            <p className="text-shield-text-muted mt-1 text-[11px]">Caps score at &le; 65/100 and triggers prominent security warning.</p>
          </div>
        </div>
      </div>
    </div>
  );
};

