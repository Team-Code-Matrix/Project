import React from 'react';
import { Send, Cpu, GitMerge, Award } from 'lucide-react';

export const HowItWorksProcess: React.FC = () => {
  const steps = [
    {
      step: '01',
      title: 'Submit URL',
      subtitle: 'Target Ingestion',
      description:
        'Enter any website URL or bare domain. The frontend strictly normalizes syntax, verifies scheme integrity, and isolates the target without browser-side execution.',
      icon: Send,
    },
    {
      step: '02',
      title: 'Independent Analysis',
      subtitle: 'Parallel Inspection',
      description:
        'Six isolated models inspect domain telemetry, TLS certificate transparency, visual form clone risks, redirect chains, and defensive header configurations.',
      icon: Cpu,
    },
    {
      step: '03',
      title: 'Signal Correlation',
      subtitle: 'Cross-Model Correlation',
      description:
        'Discrepancies are surfaced rather than smoothed away. If a domain possesses a valid SSL cert but triggers a brand-spoofing alert, malicious flags take priority.',
      icon: GitMerge,
    },
    {
      step: '04',
      title: 'Explainable Score',
      subtitle: '0–100 Trust Score',
      description:
        'Receive a composite Trust Score with plain-language rationales, categorized technical findings, and actionable safety recommendations.',
      icon: Award,
    },
  ];

  return (
    <section id="how-it-works" className="py-20 px-4 max-w-7xl mx-auto w-full text-left">
      <div className="flex flex-col items-start mb-16 border-b border-[rgba(120,135,124,0.25)] pb-8">
        <div className="inline-flex items-center gap-2 text-xs font-mono text-[#F3D081] mb-3 uppercase tracking-widest">
          <span>ASSESSMENT PIPELINE</span>
        </div>
        <h2 className="swiss-display text-3xl sm:text-4xl md:text-5xl font-black text-[#E9E6DC] mb-4">
          HOW TRUST SHIELD ASSESSES RISK.
        </h2>
        <p className="max-w-3xl text-[#B7C4B8] text-base leading-relaxed">
          Security is not a single binary state. Our multi-stage pipeline translates deep cybersecurity telemetry into clear, actionable advice.
        </p>
      </div>

      {/* Process Flow Line & Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 relative">
        {steps.map((item, index) => {
          const Icon = item.icon;
          return (
            <div
              key={item.step}
              className="rounded-2xl p-6 relative flex flex-col justify-between bg-gradient-to-br from-white/[0.04] via-[#101713]/40 to-[#080B09]/45 backdrop-blur-[3px] border border-[rgba(120,135,124,0.28)] hover:border-[#F3D081]/50 transition-all duration-300 shadow-[0_20px_45px_-10px_rgba(0,0,0,0.55),inset_0_1px_1px_0_rgba(233,230,220,0.18),inset_0_-1px_1px_0_rgba(0,0,0,0.3)] hover:shadow-[0_25px_50px_-10px_rgba(0,0,0,0.7),inset_0_1px_2px_0_rgba(243,208,129,0.3)] group"
            >
              <div>
                {/* Step header */}
                <div className="flex items-center justify-between mb-5">
                  <span className="font-mono text-xs font-bold px-2.5 py-1 rounded bg-[#080B09]/60 backdrop-blur-[2px] text-[#F3D081] border border-[rgba(120,135,124,0.3)] tracking-wider">
                    STEP {item.step}
                  </span>
                  <div className="p-2 rounded-xl bg-[#141D18]/60 backdrop-blur-[2px] border border-[rgba(120,135,124,0.3)] text-[#F3D081] group-hover:scale-110 transition-transform">
                    <Icon className="w-5 h-5" />
                  </div>
                </div>

                <div className="text-xs font-mono text-[#78877C] mb-1.5 uppercase tracking-wider font-semibold">
                  {item.subtitle}
                </div>
                <h3 className="text-lg font-bold font-sans text-[#E9E6DC] mb-3 tracking-tight group-hover:text-[#F3D081] transition-colors">
                  {item.title}
                </h3>
                <p className="text-sm text-[#B7C4B8] leading-relaxed">
                  {item.description}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
};

