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
      className="relative w-full py-10 overflow-hidden border-y border-shield-border/60 bg-[#0C120F]/60 backdrop-blur-md"
      aria-label="Trust Shield Principles"
    >
      {/* Subtle edge fade gradients */}
      <div className="absolute left-0 top-0 bottom-0 w-24 md:w-48 bg-gradient-to-r from-shield-bg to-transparent z-10 pointer-events-none" />
      <div className="absolute right-0 top-0 bottom-0 w-24 md:w-48 bg-gradient-to-l from-shield-bg to-transparent z-10 pointer-events-none" />

      <div className="flex flex-col gap-4">
        {/* Strip A: Left to Right */}
        <div className="flex overflow-hidden select-none group">
          <div
            className="flex shrink-0 items-center gap-6 animate-ticker-l2r group-hover:[animation-play-state:paused] motion-ticker-track"
            aria-hidden="true"
          >
            {duplicatedA.map((item, idx) => {
              const Icon = item.icon;
              return (
                <div
                  key={`strip-a-${idx}`}
                  className="inline-flex items-center gap-3.5 px-5 py-2.5 rounded-full bg-shield-surface/80 border border-shield-border hover:border-shield-accent-light/40 transition-colors shadow-clay-sm"
                >
                  <span className="p-1.5 rounded-full bg-shield-accent/20 text-shield-accent-light">
                    <Icon className="w-3.5 h-3.5" />
                  </span>
                  <span className="text-sm font-medium tracking-wide text-shield-text-primary whitespace-nowrap">
                    {item.text}
                  </span>
                  <span className="w-1.5 h-1.5 rounded-full bg-shield-accent/60" />
                </div>
              );
            })}
          </div>
        </div>

        {/* Strip B: Right to Left (Faster / distinct styling) */}
        <div className="flex overflow-hidden select-none group">
          <div
            className="flex shrink-0 items-center gap-6 animate-ticker-r2l group-hover:[animation-play-state:paused] motion-ticker-track"
            aria-hidden="true"
          >
            {duplicatedB.map((item, idx) => {
              const Icon = item.icon;
              return (
                <div
                  key={`strip-b-${idx}`}
                  className="inline-flex items-center gap-3.5 px-5 py-2.5 rounded-full bg-shield-surface-elevated/70 border border-shield-border/70 hover:border-shield-accent/40 transition-colors"
                >
                  <span className="p-1.5 rounded-full bg-shield-surface text-shield-accent-light/80">
                    <Icon className="w-3.5 h-3.5" />
                  </span>
                  <span className="text-sm font-mono text-shield-text-secondary whitespace-nowrap">
                    {item.text}
                  </span>
                  <span className="w-1.5 h-1.5 rounded-full bg-shield-border-strong" />
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

