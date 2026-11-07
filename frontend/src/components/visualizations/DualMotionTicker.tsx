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
      className="relative w-full py-8 overflow-hidden border-y border-[rgba(120,135,124,0.25)] bg-[#080B09]/80 backdrop-blur-md"
      aria-label="Trust Shield Principles"
    >
      {/* Subtle edge fade gradients */}
      <div className="absolute left-0 top-0 bottom-0 w-24 md:w-48 bg-gradient-to-r from-[#080B09] to-transparent z-10 pointer-events-none" />
      <div className="absolute right-0 top-0 bottom-0 w-24 md:w-48 bg-gradient-to-l from-[#080B09] to-transparent z-10 pointer-events-none" />

      <div className="flex flex-col gap-3">
        {/* Strip A: Left to Right */}
        <div className="flex overflow-hidden select-none group">
          <div
            className="flex shrink-0 items-center gap-4 animate-ticker-l2r group-hover:[animation-play-state:paused] motion-ticker-track"
            aria-hidden="true"
          >
            {duplicatedA.map((item, idx) => {
              const Icon = item.icon;
              return (
                <div
                  key={`strip-a-${idx}`}
                  className="inline-flex items-center gap-3 px-4 py-2 rounded-xl bg-[#101713] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/50 transition-colors shadow-sm"
                >
                  <span className="p-1 rounded-lg bg-[#141D18] text-[#F3D081]">
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

        {/* Strip B: Right to Left (Faster / distinct styling) */}
        <div className="flex overflow-hidden select-none group">
          <div
            className="flex shrink-0 items-center gap-4 animate-ticker-r2l group-hover:[animation-play-state:paused] motion-ticker-track"
            aria-hidden="true"
          >
            {duplicatedB.map((item, idx) => {
              const Icon = item.icon;
              return (
                <div
                  key={`strip-b-${idx}`}
                  className="inline-flex items-center gap-3 px-4 py-2 rounded-xl bg-[#141D18]/90 border border-[rgba(120,135,124,0.2)] hover:border-[#F3D081]/40 transition-colors"
                >
                  <span className="p-1 rounded-lg bg-[#080B09] text-[#B7C4B8]">
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

