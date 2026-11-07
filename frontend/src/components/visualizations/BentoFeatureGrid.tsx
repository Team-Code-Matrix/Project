import React from 'react';
import {
  ShieldAlert,
  Globe2,
  Lock,
  GitFork,
  FileCheck2,
  Users2,
  ArrowUpRight,
  Fingerprint,
  Layers,
} from 'lucide-react';

export const BentoFeatureGrid: React.FC = () => {
  return (
    <section id="features" className="py-20 px-4 max-w-7xl mx-auto w-full text-left">
      <div className="flex flex-col items-center text-center mb-14">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-shield-surface border border-shield-border text-xs font-mono text-shield-accent-light mb-4">
          <Layers className="w-3.5 h-3.5" />
          <span>MULTI-MODEL ARCHITECTURE</span>
        </div>
        <h2 className="text-3xl md:text-4xl lg:text-5xl font-bold tracking-tight text-shield-text-primary mb-4">
          Six independent security layers.
          <br />
          <span className="text-shield-accent-light">One correlated trust verdict.</span>
        </h2>
        <p className="max-w-2xl text-shield-text-secondary text-base md:text-lg leading-relaxed">
          Rather than relying on a single binary check, Trust Shield evaluates website legitimacy across specialized intelligence domains to illuminate hidden risks.
        </p>
      </div>

      {/* Bento Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-12 gap-5">
        {/* Card 1: Phishing Detection (Span 7) */}
        <div className="lg:col-span-7 clay-card rounded-2xl p-7 flex flex-col justify-between group relative overflow-hidden">
          <div className="absolute top-0 right-0 p-8 opacity-5 group-hover:opacity-10 transition-opacity">
            <ShieldAlert className="w-48 h-48 text-shield-accent-light" />
          </div>

          <div>
            <div className="flex items-center justify-between mb-5">
              <div className="p-3 rounded-xl bg-shield-accent/20 border border-shield-accent/30 text-shield-accent-light">
                <Fingerprint className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-shield-accent-light/80 bg-shield-surface-elevated px-2.5 py-1 rounded-md border border-shield-border">
                MODEL 01 // DOMAIN & FORM
              </span>
            </div>

            <h3 className="text-xl md:text-2xl font-bold text-shield-text-primary mb-2.5 group-hover:text-shield-accent-light transition-colors">
              Phishing & Brand Impersonation Detection
            </h3>
            <p className="text-shield-text-secondary text-sm md:text-base leading-relaxed mb-6">
              Detects structural visual clones, brand asset piracy, and unauthorized credential intake endpoints. Identifies deceptive forms designed to harvest passwords or MFA tokens before users type.
            </p>
          </div>

          {/* Interactive telemetry mock widget */}
          <div className="bg-[#0B100E]/70 rounded-xl p-4 border border-shield-border/70 font-mono text-xs text-shield-text-secondary space-y-2">
            <div className="flex justify-between items-center text-shield-text-primary border-b border-shield-border/40 pb-2">
              <span className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-shield-accent-light animate-pulse" />
                Live Heuristic Sensor
              </span>
              <span className="text-shield-success">Active Pipeline</span>
            </div>
            <div className="flex justify-between">
              <span>Brand Divergence Metric:</span>
              <span className="text-shield-text-primary">Levenshtein &lt; 2 flags</span>
            </div>
            <div className="flex justify-between">
              <span>Form Action Extraction:</span>
              <span className="text-shield-accent-light">First-Party / Sandboxed</span>
            </div>
          </div>
        </div>

        {/* Card 2: Domain Intelligence (Span 5) */}
        <div className="lg:col-span-5 clay-card rounded-2xl p-7 flex flex-col justify-between group relative overflow-hidden">
          <div>
            <div className="flex items-center justify-between mb-5">
              <div className="p-3 rounded-xl bg-shield-accent/20 border border-shield-accent/30 text-shield-accent-light">
                <Globe2 className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-shield-accent-light/80 bg-shield-surface-elevated px-2.5 py-1 rounded-md border border-shield-border">
                MODEL 02 // REPUTATION
              </span>
            </div>

            <h3 className="text-xl font-bold text-shield-text-primary mb-2.5 group-hover:text-shield-accent-light transition-colors">
              URL & Domain Intelligence
            </h3>
            <p className="text-shield-text-secondary text-sm leading-relaxed mb-5">
              Inspects domain lifespan, registrar stability, Shannon lexical entropy, and punycode homograph tricks (e.g. Cyrillic letter substitution in web addresses).
            </p>
          </div>

          <div className="bg-[#0B100E]/70 rounded-xl p-3.5 border border-shield-border/70 font-mono text-xs space-y-1.5 text-shield-text-secondary">
            <div className="flex justify-between">
              <span>Shannon Entropy:</span>
              <span className="text-shield-accent-light">1.94 (Natural Stem)</span>
            </div>
            <div className="flex justify-between">
              <span>Punycode De-obfuscation:</span>
              <span className="text-shield-success">ASCII Clean</span>
            </div>
          </div>
        </div>

        {/* Card 3: TLS & Certificate Analysis (Span 4) */}
        <div className="lg:col-span-4 clay-card rounded-2xl p-7 flex flex-col justify-between group">
          <div>
            <div className="flex items-center justify-between mb-5">
              <div className="p-3 rounded-xl bg-shield-accent/20 border border-shield-accent/30 text-shield-accent-light">
                <Lock className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-shield-accent-light/80 bg-shield-surface-elevated px-2.5 py-1 rounded-md border border-shield-border">
                MODEL 03 // CRYPTO
              </span>
            </div>

            <h3 className="text-lg md:text-xl font-bold text-shield-text-primary mb-2 group-hover:text-shield-accent-light transition-colors">
              TLS Certificate & Chain Validation
            </h3>
            <p className="text-shield-text-secondary text-xs md:text-sm leading-relaxed mb-4">
              A padlock only verifies encryption, not legitimacy. We dissect the Certificate Authority, Certificate Transparency (SCT), SAN host match, and cipher deprecations.
            </p>
          </div>

          <div className="mt-4 pt-3 border-t border-shield-border/50 flex items-center justify-between text-xs font-mono text-shield-text-secondary">
            <span>Audit: X.509 v3 Strict</span>
            <span className="text-shield-success">CA Verified</span>
          </div>
        </div>

        {/* Card 4: Redirect Chain Analysis (Span 4) */}
        <div className="lg:col-span-4 clay-card rounded-2xl p-7 flex flex-col justify-between group">
          <div>
            <div className="flex items-center justify-between mb-5">
              <div className="p-3 rounded-xl bg-shield-accent/20 border border-shield-accent/30 text-shield-accent-light">
                <GitFork className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-shield-accent-light/80 bg-shield-surface-elevated px-2.5 py-1 rounded-md border border-shield-border">
                MODEL 04 // ROUTING
              </span>
            </div>

            <h3 className="text-lg md:text-xl font-bold text-shield-text-primary mb-2 group-hover:text-shield-accent-light transition-colors">
              Redirect Chain & Shortener Traversal
            </h3>
            <p className="text-shield-text-secondary text-xs md:text-sm leading-relaxed mb-4">
              Traces HTTP 301, 302, 307 hops and client-side meta-refreshes. Follows shortened URLs across jurisdictions to reveal the unrated final landing host.
            </p>
          </div>

          <div className="mt-4 pt-3 border-t border-shield-border/50 flex items-center justify-between text-xs font-mono text-shield-text-secondary">
            <span>Autonomous System Hops</span>
            <span className="text-shield-accent-light">Bounded Max 5</span>
          </div>
        </div>

        {/* Card 5: Web Security Posture (Span 4) */}
        <div className="lg:col-span-4 clay-card rounded-2xl p-7 flex flex-col justify-between group">
          <div>
            <div className="flex items-center justify-between mb-5">
              <div className="p-3 rounded-xl bg-shield-accent/20 border border-shield-accent/30 text-shield-accent-light">
                <FileCheck2 className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-shield-accent-light/80 bg-shield-surface-elevated px-2.5 py-1 rounded-md border border-shield-border">
                MODEL 05 // HYGIENE
              </span>
            </div>

            <h3 className="text-lg md:text-xl font-bold text-shield-text-primary mb-2 group-hover:text-shield-accent-light transition-colors">
              Web Security Posture
            </h3>
            <p className="text-shield-text-secondary text-xs md:text-sm leading-relaxed mb-4">
              Evaluates non-invasive defensive headers: HSTS preload, Content-Security-Policy (CSP), X-Frame-Options against clickjacking, and cookie isolation.
            </p>
          </div>

          <div className="mt-4 pt-3 border-t border-shield-border/50 flex items-center justify-between text-xs font-mono text-shield-text-secondary">
            <span>RFC Compliance</span>
            <span className="text-shield-success">OWASP Top 10 Aligned</span>
          </div>
        </div>

        {/* Card 6: Collaborative Threat Intelligence (Span 12 - Wide Feature) */}
        <div className="lg:col-span-12 clay-card rounded-2xl p-7 md:p-8 flex flex-col md:flex-row items-center justify-between gap-6 group relative overflow-hidden bg-gradient-to-r from-shield-surface via-[#141E18] to-shield-surface-elevated">
          <div className="space-y-3 max-w-2xl">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-shield-accent/20 border border-shield-accent/30 text-shield-accent-light">
                <Users2 className="w-5 h-5" />
              </div>
              <span className="text-xs font-mono text-shield-accent-light/80 uppercase tracking-wider">
                MODEL 06 // COLLECTIVE SENSORS
              </span>
            </div>
            <h3 className="text-xl md:text-2xl font-bold text-shield-text-primary">
              Collaborative Threat Intelligence & Feeds
            </h3>
            <p className="text-shield-text-secondary text-sm md:text-base leading-relaxed">
              Synthesizes real-time reports from our global analyst community with curated partner threat feeds (PhishTank, URLhaus, AlienVault OTX, and honeypot network telemetry).
            </p>
          </div>

          <div className="flex flex-col sm:flex-row gap-3 w-full md:w-auto shrink-0">
            <a
              href="#threat-intel"
              className="clay-button-secondary px-5 py-3 rounded-xl text-xs md:text-sm font-medium text-shield-text-primary inline-flex items-center justify-center gap-2"
            >
              <span>Explore Threat Intel</span>
              <ArrowUpRight className="w-4 h-4 text-shield-accent-light" />
            </a>
          </div>
        </div>
      </div>
    </section>
  );
};
