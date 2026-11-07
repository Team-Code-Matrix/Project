import React from 'react';
import { Send, Cpu, GitMerge, Award, AlertCircle } from 'lucide-react';

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
      subtitle: 'Bayesian Fusion',
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
    <section id="how-it-works" className="py-20 px-4 max-w-7xl mx-auto w-full">
      <div className="flex flex-col items-center text-center mb-16">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-shield-surface border border-shield-border text-xs font-mono text-shield-accent-light mb-4">
          <span>PIPELINE WORKFLOW</span>
        </div>
        <h2 className="text-3xl md:text-4xl font-bold tracking-tight text-shield-text-primary mb-4">
          How Trust Shield assesses risk.
        </h2>
        <p className="max-w-2xl text-shield-text-secondary text-base leading-relaxed">
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
              className="clay-card rounded-2xl p-6 relative flex flex-col justify-between border border-shield-border/80 group hover:border-shield-accent/50 transition-all"
            >
              <div>
                {/* Step header */}
                <div className="flex items-center justify-between mb-5">
                  <span className="font-mono text-xs font-bold px-2.5 py-1 rounded-md bg-shield-surface-elevated text-shield-accent-light border border-shield-border">
                    PHASE {item.step}
                  </span>
                  <div className="p-2 rounded-xl bg-shield-accent/15 text-shield-accent-light group-hover:scale-110 transition-transform">
                    <Icon className="w-5 h-5" />
                  </div>
                </div>

                <div className="text-xs font-mono text-shield-text-muted mb-1 uppercase tracking-wider">
                  {item.subtitle}
                </div>
                <h3 className="text-lg font-bold text-shield-text-primary mb-3">
                  {item.title}
                </h3>
                <p className="text-sm text-shield-text-secondary leading-relaxed">
                  {item.description}
                </p>
              </div>

              <div className="mt-6 pt-4 border-t border-shield-border/40 flex items-center justify-between text-xs font-mono text-shield-text-muted">
                <span>STAGE {index + 1} OF 4</span>
                <span className="w-1.5 h-1.5 rounded-full bg-shield-accent-light" />
              </div>
            </div>
          );
        })}
      </div>

      {/* Transparency Callout */}
      <div className="mt-10 p-5 rounded-xl bg-shield-surface/60 border border-shield-border/80 flex items-start gap-3.5 max-w-3xl mx-auto">
        <AlertCircle className="w-5 h-5 text-shield-accent-light shrink-0 mt-0.5" />
        <div className="text-xs md:text-sm text-shield-text-secondary leading-relaxed">
          <strong className="text-shield-text-primary font-medium">Important Methodology Note:</strong> Individual models operate autonomously and may disagree. An overall score represents observed risk in performed checks and is not an absolute guarantee of safety. Critical indicators override numerical scores.
        </div>
      </div>
    </section>
  );
};

