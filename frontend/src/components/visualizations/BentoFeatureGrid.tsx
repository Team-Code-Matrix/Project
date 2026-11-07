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

/**
 * Frosted Glass Surface Material (Glossiness = 0.8)
 * - Calibrated to match the high-transparency URL scanner box
 * - Translucent obsidian/forest gradient base (38-45% opacity)
 * - Lightweight 3px background blur so ASCII world map is clearly visible through the glass
 * - Specular top-edge refraction highlight (inset 0 1px 1px rgba(233,230,220,0.20))
 * - Soft translucent architectural border (rgba(120,135,124,0.28))
 * - Interactive champagne gold hover luminescence
 */
const FROSTED_GLASS_08 =
  'bg-gradient-to-br from-white/[0.04] via-[#101713]/38 via-35% to-[#080B09]/45 backdrop-blur-[3px] backdrop-saturate-[120%] border border-[rgba(120,135,124,0.28)] hover:border-[#F3D081]/50 transition-all duration-300 shadow-[0_20px_45px_-10px_rgba(0,0,0,0.55),inset_0_1px_1px_0_rgba(233,230,220,0.20),inset_0_-1px_1px_0_rgba(0,0,0,0.3)] hover:shadow-[0_25px_50px_-10px_rgba(0,0,0,0.7),inset_0_1px_2px_0_rgba(243,208,129,0.35),inset_0_-1px_1px_0_rgba(0,0,0,0.35)]';

export const BentoFeatureGrid: React.FC = () => {
  return (
    <section id="features" className="py-20 px-4 max-w-7xl mx-auto w-full text-left">
      <div className="flex flex-col items-start mb-14 border-b border-[rgba(120,135,124,0.25)] pb-8">
        <div className="inline-flex items-center gap-2 text-xs font-mono text-[#F3D081] mb-3 uppercase tracking-widest">
          <Layers className="w-3.5 h-3.5 text-[#F3D081]" />
          <span>DETECTION ARCHITECTURE</span>
        </div>
        <h2 className="swiss-display text-3xl sm:text-4xl md:text-5xl lg:text-6xl font-black text-[#E9E6DC] mb-4">
          SIX INDEPENDENT SECURITY LAYERS.
          <br />
          <span className="text-[#F3D081]">ONE CORRELATED TRUST VERDICT.</span>
        </h2>
        <p className="max-w-3xl text-[#B7C4B8] text-base md:text-lg leading-relaxed">
          Rather than relying on a single binary check, Trust Shield evaluates website legitimacy across specialized intelligence domains to illuminate hidden risks.
        </p>
      </div>

      {/* Bento Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-12 gap-5">
        {/* Card 1: Phishing Detection (Span 7) */}
        <div className={`lg:col-span-7 rounded-2xl p-7 flex flex-col justify-between group relative overflow-hidden ${FROSTED_GLASS_08}`}>
          <div className="absolute top-0 right-0 p-8 opacity-5 group-hover:opacity-10 transition-opacity">
            <ShieldAlert className="w-48 h-48 text-[#F3D081]" />
          </div>

          <div>
            <div className="flex items-center justify-between mb-5">
              <div className="p-3 rounded-xl bg-[#141D18]/70 backdrop-blur-[2px] border border-[rgba(120,135,124,0.3)] text-[#F3D081]">
                <Fingerprint className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-[#F3D081] bg-[#080B09] px-2.5 py-1 rounded-md border border-[rgba(120,135,124,0.3)] uppercase tracking-wider font-semibold">
                Phishing & Forms
              </span>
            </div>

            <h3 className="text-xl md:text-2xl font-bold font-sans text-[#E9E6DC] mb-2.5 group-hover:text-[#F3D081] transition-colors tracking-tight">
              Phishing & Brand Impersonation Detection
            </h3>
            <p className="text-[#B7C4B8] text-sm md:text-base leading-relaxed">
              Detects structural visual clones, brand asset piracy, and unauthorized credential intake endpoints. Identifies deceptive forms designed to harvest passwords or MFA tokens before users type.
            </p>
          </div>
        </div>

        {/* Card 2: Domain Intelligence (Span 5) */}
        <div className={`lg:col-span-5 rounded-2xl p-7 flex flex-col justify-between group relative overflow-hidden ${FROSTED_GLASS_08}`}>
          <div>
            <div className="flex items-center justify-between mb-5">
              <div className="p-3 rounded-xl bg-[#141D18]/70 backdrop-blur-[2px] border border-[rgba(120,135,124,0.3)] text-[#F3D081]">
                <Globe2 className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-[#F3D081] bg-[#080B09] px-2.5 py-1 rounded-md border border-[rgba(120,135,124,0.3)] uppercase tracking-wider font-semibold">
                Domain Intel
              </span>
            </div>

            <h3 className="text-xl font-bold font-sans text-[#E9E6DC] mb-2.5 group-hover:text-[#F3D081] transition-colors tracking-tight">
              URL & Domain Intelligence
            </h3>
            <p className="text-[#B7C4B8] text-sm leading-relaxed">
              Inspects domain lifespan, registrar stability, Shannon lexical entropy, and punycode homograph tricks (e.g. Cyrillic letter substitution in web addresses).
            </p>
          </div>
        </div>

        {/* Card 3: TLS & Certificate Analysis (Span 4) */}
        <div className={`lg:col-span-4 rounded-2xl p-7 flex flex-col justify-between group relative overflow-hidden ${FROSTED_GLASS_08}`}>
          <div>
            <div className="flex items-center justify-between mb-5">
              <div className="p-3 rounded-xl bg-[#141D18]/70 backdrop-blur-[2px] border border-[rgba(120,135,124,0.3)] text-[#F3D081]">
                <Lock className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-[#F3D081] bg-[#080B09] px-2.5 py-1 rounded-md border border-[rgba(120,135,124,0.3)] uppercase tracking-wider font-semibold">
                TLS & Crypto
              </span>
            </div>

            <h3 className="text-lg md:text-xl font-bold font-sans text-[#E9E6DC] mb-2 group-hover:text-[#F3D081] transition-colors tracking-tight">
              TLS Certificate & Chain Validation
            </h3>
            <p className="text-[#B7C4B8] text-xs md:text-sm leading-relaxed">
              A padlock only verifies encryption, not legitimacy. We dissect the Certificate Authority, Certificate Transparency (SCT), SAN host match, and cipher deprecations.
            </p>
          </div>
        </div>

        {/* Card 4: Redirect Chain Analysis (Span 4) */}
        <div className={`lg:col-span-4 rounded-2xl p-7 flex flex-col justify-between group relative overflow-hidden ${FROSTED_GLASS_08}`}>
          <div>
            <div className="flex items-center justify-between mb-5">
              <div className="p-3 rounded-xl bg-[#141D18]/70 backdrop-blur-[2px] border border-[rgba(120,135,124,0.3)] text-[#F3D081]">
                <GitFork className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-[#F3D081] bg-[#080B09] px-2.5 py-1 rounded-md border border-[rgba(120,135,124,0.3)] uppercase tracking-wider font-semibold">
                Redirect Trace
              </span>
            </div>

            <h3 className="text-lg md:text-xl font-bold font-sans text-[#E9E6DC] mb-2 group-hover:text-[#F3D081] transition-colors tracking-tight">
              Redirect Chain & Shortener Traversal
            </h3>
            <p className="text-[#B7C4B8] text-xs md:text-sm leading-relaxed">
              Traces HTTP 301, 302, 307 hops and client-side meta-refreshes. Follows shortened URLs across jurisdictions to reveal the unrated final landing host.
            </p>
          </div>
        </div>

        {/* Card 5: Web Security Posture (Span 4) */}
        <div className={`lg:col-span-4 rounded-2xl p-7 flex flex-col justify-between group relative overflow-hidden ${FROSTED_GLASS_08}`}>
          <div>
            <div className="flex items-center justify-between mb-5">
              <div className="p-3 rounded-xl bg-[#141D18]/70 backdrop-blur-[2px] border border-[rgba(120,135,124,0.3)] text-[#F3D081]">
                <FileCheck2 className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-[#F3D081] bg-[#080B09] px-2.5 py-1 rounded-md border border-[rgba(120,135,124,0.3)] uppercase tracking-wider font-semibold">
                Web Hygiene
              </span>
            </div>

            <h3 className="text-lg md:text-xl font-bold font-sans text-[#E9E6DC] mb-2 group-hover:text-[#F3D081] transition-colors tracking-tight">
              Web Security Posture
            </h3>
            <p className="text-[#B7C4B8] text-xs md:text-sm leading-relaxed">
              Evaluates non-invasive defensive headers: HSTS preload, Content-Security-Policy (CSP), X-Frame-Options against clickjacking, and cookie isolation.
            </p>
          </div>
        </div>

        {/* Card 6: Collaborative Threat Intelligence (Span 12 - Wide Feature) */}
        <div className={`lg:col-span-12 rounded-2xl p-7 md:p-8 flex flex-col md:flex-row items-center justify-between gap-6 group relative overflow-hidden ${FROSTED_GLASS_08}`}>
          <div className="space-y-3 max-w-2xl">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-[#141D18]/70 backdrop-blur-[2px] border border-[rgba(120,135,124,0.3)] text-[#F3D081]">
                <Users2 className="w-5 h-5" />
              </div>
              <span className="text-xs font-mono text-[#F3D081] uppercase tracking-wider font-bold">
                Threat Feeds
              </span>
            </div>
            <h3 className="text-xl md:text-2xl font-bold font-sans text-[#E9E6DC]">
              Collaborative Threat Intelligence & Feeds
            </h3>
            <p className="text-[#B7C4B8] text-sm md:text-base leading-relaxed">
              Synthesizes real-time reports from our global analyst community with curated partner threat feeds (PhishTank, URLhaus, AlienVault OTX, and honeypot network telemetry).
            </p>
          </div>

          <div className="flex flex-col sm:flex-row gap-3 w-full md:w-auto shrink-0">
            <a
              href="#threat-intel"
              className="px-5 py-3 rounded-xl text-xs md:text-sm font-mono font-bold tracking-wider uppercase text-[#E9E6DC] bg-[#141D18]/80 backdrop-blur-[2px] border border-[rgba(120,135,124,0.4)] hover:border-[#F3D081] hover:text-[#F3D081] transition-all inline-flex items-center justify-center gap-2 cursor-pointer"
            >
              <span>Explore Threat Intel</span>
              <ArrowUpRight className="w-4 h-4 text-[#F3D081]" />
            </a>
          </div>
        </div>
      </div>
    </section>
  );
};
