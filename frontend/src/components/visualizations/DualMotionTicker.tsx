import React from 'react';
import { Shield, Lock, Eye, Activity, Terminal, CheckCircle2, Cpu, Globe } from 'lucide-react';

export const DualMotionTicker: React.FC = () => {
  const stripAItems = [
    { text: 'Trust begins with verification', icon: Shield },
    { text: 'Inspect before you interact', icon: Eye },
    { text: 'Beyond the browser lock icon', icon: Lock },
    { text: 'Every signal matters', icon: Activity },
    { text: 'Understand the risk profile', icon: Terminal },
    { text: 'Multi-model correlation', icon: Cpu },
  ];

  const stripBItems = [
    { text: 'Security through intelligence', icon: Shield },
    { text: 'Verify the identity behind the domain', icon: Globe },
    { text: 'Make informed decisions', icon: CheckCircle2 },
    { text: 'Zero implicit trust', icon: Lock },
    { text: 'Community telemetry feed', icon: Activity },
    { text: 'Explainable threat indicators', icon: Eye },
  ];

  // Duplicate items for continuous seamless loop
  const duplicatedA = [...stripAItems, ...stripAItems, ...stripAItems, ...stripAItems];
  const duplicatedB = [...stripBItems, ...stripBItems, ...stripBItems, ...stripBItems];

  return (
    <div
      className="relative w-full py-9 overflow-hidden border-y border-[rgba(120,135,124,0.25)] bg-[#080B09]/80 backdrop-blur-md"
      aria-label="Trust Shield Principles"
    >
      {/* Fixed Central Subtle Radial Glow (Champagne Gold / Soft Sepia) */}
      <div
        aria-hidden="true"
        className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-[650px] md:w-[900px] h-[240px] pointer-events-none z-0"
        style={{
          background:
            'radial-gradient(ellipse 60% 50% at 50% 50%, rgba(243, 208, 129, 0.08) 0%, rgba(181, 145, 91, 0.045) 45%, rgba(112, 91, 68, 0.015) 70%, transparent 100%)',
        }}
      />

      {/* Subtle edge fade gradients */}
      <div className="absolute left-0 top-0 bottom-0 w-24 md:w-48 bg-gradient-to-r from-[#080B09] to-transparent z-20 pointer-events-none" />
      <div className="absolute right-0 top-0 bottom-0 w-24 md:w-48 bg-gradient-to-l from-[#080B09] to-transparent z-20 pointer-events-none" />

      <div className="flex flex-col gap-3.5 relative z-10">
        {/* Strip A: Left to Right */}
        <div className="flex overflow-hidden select-none">
          <div
            className="flex shrink-0 items-center gap-4 animate-ticker-l2r motion-ticker-track"
            aria-hidden="true"
            style={{ animationPlayState: 'running' }}
          >
            {duplicatedA.map((item, idx) => {
              const Icon = item.icon;
              return (
                <div
                  key={`strip-a-${idx}`}
                  className="inline-flex items-center gap-3 px-5 py-2.5 rounded-xl bg-[#101713]/50 backdrop-blur-[3px] border border-[rgba(120,135,124,0.28)] hover:border-[#F3D081]/60 transition-colors shadow-sm"
                >
                  <span className="p-1.5 rounded-lg bg-[#141D18]/60 backdrop-blur-[2px] text-[#F3D081] border border-[rgba(120,135,124,0.2)]">
                    <Icon className="w-3.5 h-3.5" />
                  </span>
                  <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#E9E6DC] whitespace-nowrap">
                    {item.text}
                  </span>
                  <span className="w-1.5 h-1.5 rounded-full bg-[#F3D081]" />
                </div>
              );
            })}
          </div>
        </div>

        {/* Strip B: Right to Left */}
        <div className="flex overflow-hidden select-none">
          <div
            className="flex shrink-0 items-center gap-4 animate-ticker-r2l motion-ticker-track"
            aria-hidden="true"
            style={{ animationPlayState: 'running' }}
          >
            {duplicatedB.map((item, idx) => {
              const Icon = item.icon;
              return (
                <div
                  key={`strip-b-${idx}`}
                  className="inline-flex items-center gap-3 px-5 py-2.5 rounded-xl bg-[#141D18]/50 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/50 transition-colors"
                >
                  <span className="p-1.5 rounded-lg bg-[#080B09]/60 backdrop-blur-[2px] text-[#B7C4B8] border border-[rgba(120,135,124,0.2)]">
                    <Icon className="w-3.5 h-3.5" />
                  </span>
                  <span className="text-xs font-mono text-[#B7C4B8] whitespace-nowrap tracking-wide">
                    {item.text}
                  </span>
                  <span className="w-1.5 h-1.5 rounded-full bg-[#78877C]" />
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

