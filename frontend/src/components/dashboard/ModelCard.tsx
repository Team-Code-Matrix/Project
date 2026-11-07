import React, { useState } from 'react';
import type { ModelResult } from '../../types/scan';
import { VerdictBadge } from '../shared/VerdictBadge';
import {
  ChevronDown,
  ChevronUp,
  Clock,
  Terminal,
} from 'lucide-react';

interface ModelCardProps {
  model: ModelResult;
}

export const ModelCard: React.FC<ModelCardProps> = ({ model }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  // Border and accent based on verdict
  const getVerdictAccent = () => {
    switch (model.verdict) {
      case 'malicious':
        return 'border-rose-500/40 hover:border-rose-500/60 shadow-[0_4px_20px_rgba(217,120,120,0.12)]';
      case 'suspicious':
        return 'border-amber-500/35 hover:border-amber-500/50 shadow-[0_4px_20px_rgba(215,170,98,0.1)]';
      case 'clear':
        return 'border-shield-border hover:border-shield-accent/50';
      case 'error':
        return 'border-red-500/30 hover:border-red-500/50';
      case 'skipped':
      case 'unknown':
      default:
        return 'border-shield-border/60 hover:border-shield-border';
    }
  };

  return (
    <div
      className={`clay-card rounded-2xl p-6 transition-all border ${getVerdictAccent()} flex flex-col justify-between text-left`}
    >
      <div>
        {/* Model Header */}
        <div className="flex items-start justify-between gap-3 mb-4">
          <div className="flex items-center gap-3">
            <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-shield-surface-elevated text-shield-accent-light border border-shield-border">
              M-{model.number}
            </span>
            <span className="text-xs font-mono text-shield-text-muted uppercase tracking-wider">
              {model.category}
            </span>
          </div>

          <VerdictBadge verdict={model.verdict} />
        </div>

        {/* Model Title & Description */}
        <h3 className="text-lg font-bold text-shield-text-primary mb-2">
          {model.name}
        </h3>
        <p className="text-xs text-shield-text-secondary leading-relaxed mb-4">
          {model.description}
        </p>

        {/* Model Verdict Summary */}
        <div className="p-3.5 rounded-xl bg-shield-surface-elevated/80 border border-shield-border/60 text-xs text-shield-text-primary mb-4 leading-relaxed">
          {model.summary}
        </div>

        {/* Metrics Grid if available */}
        {model.metrics && model.metrics.length > 0 && (
          <div className="grid grid-cols-2 gap-2 mb-4 font-mono text-[11px]">
            {model.metrics.map((metric, idx) => (
              <div
                key={idx}
                className="p-2 rounded-lg bg-shield-surface/80 border border-shield-border/40 flex flex-col"
              >
                <span className="text-shield-text-muted truncate">{metric.label}</span>
                <span
                  className={`font-semibold truncate ${
                    metric.state === 'alert'
                      ? 'text-shield-danger'
                      : metric.state === 'warn'
                      ? 'text-shield-warning'
                      : 'text-shield-text-primary'
                  }`}
                >
                  {metric.value}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Footer / Expand Evidence Section */}
      <div className="pt-3 border-t border-shield-border/50">
        <div className="flex items-center justify-between text-xs font-mono text-shield-text-muted mb-2">
          {model.confidence !== undefined ? (
            <span>
              Confidence: <strong className="text-shield-text-primary">{model.confidence}%</strong>
            </span>
          ) : (
            <span>Confidence: N/A</span>
          )}

          {model.executionTimeMs && (
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {model.executionTimeMs}ms
            </span>
          )}
        </div>

        {/* Toggle Evidence */}
        {model.evidence && model.evidence.length > 0 && (
          <div>
            <button
              type="button"
              onClick={() => setIsExpanded(!isExpanded)}
              className="w-full mt-1 py-1.5 px-3 rounded-lg bg-shield-surface-elevated/60 hover:bg-shield-surface-elevated text-xs font-mono text-shield-accent-light flex items-center justify-between transition-colors border border-shield-border/40 cursor-pointer"
            >
              <span className="flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5" />
                {isExpanded ? 'Hide Technical Evidence' : `View Evidence (${model.evidence.length})`}
              </span>
              {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>

            {isExpanded && (
              <div className="mt-2.5 p-3 rounded-xl bg-[#090E0C] border border-shield-border/70 font-mono text-[11px] text-shield-text-secondary space-y-1.5 animate-fadeIn">
                {model.evidence.map((line, idx) => (
                  <div key={idx} className="flex items-start gap-2">
                    <span className="text-shield-accent-light shrink-0">&gt;</span>
                    <span className="break-all">{line}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
