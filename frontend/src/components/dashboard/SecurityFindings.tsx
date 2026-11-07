import React, { useState } from 'react';
import type { Finding, FindingSeverity } from '../../types/scan';
import { SeverityBadge } from '../shared/SeverityBadge';
import {
  ChevronDown,
  ChevronUp,
  Terminal,
  ArrowRight,
} from 'lucide-react';

interface SecurityFindingsProps {
  findings: Finding[];
}

export const SecurityFindings: React.FC<SecurityFindingsProps> = ({ findings }) => {
  const [activeFilter, setActiveFilter] = useState<'all' | FindingSeverity>('all');
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});

  const toggleExpand = (id: string) => {
    setExpandedFindings((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const filteredFindings = findings.filter((f) => {
    if (activeFilter === 'all') return true;
    return f.severity === activeFilter;
  });

  const severityCounts: Record<FindingSeverity, number> = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    informational: findings.filter((f) => f.severity === 'informational').length,
  };

  return (
    <div className="clay-card rounded-2xl p-6 md:p-8 space-y-6 text-left">
      {/* Header and Filter Buttons */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-shield-border/60">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h2 className="text-xl md:text-2xl font-bold text-shield-text-primary">
              Security Findings & Observed Indicators
            </h2>
            <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-shield-surface-elevated text-shield-accent-light border border-shield-border">
              {findings.length}
            </span>
          </div>
          <p className="text-xs text-shield-text-secondary">
            Specific signals detected by independent models with supporting evidence
          </p>
        </div>

        {/* Severity Filter Tabs */}
        <div className="flex flex-wrap items-center gap-1.5 p-1 rounded-xl bg-shield-surface-elevated border border-shield-border text-xs font-mono">
          <button
            type="button"
            onClick={() => setActiveFilter('all')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
              activeFilter === 'all'
                ? 'bg-shield-accent text-white font-semibold'
                : 'text-shield-text-secondary hover:text-shield-text-primary'
            }`}
          >
            All ({findings.length})
          </button>

          {(['critical', 'high', 'medium', 'low', 'informational'] as FindingSeverity[]).map(
            (sev) => {
              const count = severityCounts[sev];
              if (count === 0) return null;
              return (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setActiveFilter(sev)}
                  className={`px-2.5 py-1.5 rounded-lg uppercase transition-colors cursor-pointer ${
                    activeFilter === sev
                      ? 'bg-shield-accent text-white font-semibold'
                      : 'text-shield-text-secondary hover:text-shield-text-primary'
                  }`}
                >
                  {sev} ({count})
                </button>
              );
            }
          )}
        </div>
      </div>

      {/* Findings List */}
      {filteredFindings.length === 0 ? (
        <div className="py-12 text-center text-sm text-shield-text-secondary">
          No findings observed for filter "{activeFilter}".
        </div>
      ) : (
        <div className="space-y-4">
          {filteredFindings.map((finding) => {
            const isExpanded = !!expandedFindings[finding.id];

            return (
              <div
                key={finding.id}
                className="rounded-xl border border-shield-border/80 bg-shield-surface/50 hover:bg-shield-surface/80 transition-all overflow-hidden"
              >
                {/* Finding Header Item */}
                <div
                  onClick={() => toggleExpand(finding.id)}
                  className="p-4 md:p-5 flex items-start justify-between gap-4 cursor-pointer select-none"
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      toggleExpand(finding.id);
                    }
                  }}
                >
                  <div className="space-y-2 flex-1">
                    <div className="flex flex-wrap items-center gap-2.5">
                      <SeverityBadge severity={finding.severity} />
                      <span className="text-xs font-mono text-shield-text-muted">
                        Source: <span className="text-shield-text-secondary">{finding.source}</span>
                      </span>
                    </div>

                    <h3 className="text-base md:text-lg font-bold text-shield-text-primary">
                      {finding.title}
                    </h3>

                    <p className="text-xs md:text-sm text-shield-text-secondary leading-relaxed">
                      {finding.description}
                    </p>
                  </div>

                  <div className="p-1 rounded-lg bg-shield-surface-elevated text-shield-text-secondary shrink-0 mt-1">
                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4" />
                    ) : (
                      <ChevronDown className="w-4 h-4" />
                    )}
                  </div>
                </div>

                {/* Expandable Evidence & Recommendations */}
                {isExpanded && (
                  <div className="px-4 md:px-5 pb-5 pt-2 border-t border-shield-border/50 bg-[#080D0A]/60 space-y-4 text-xs font-mono">
                    {finding.evidence && finding.evidence.length > 0 && (
                      <div>
                        <div className="text-shield-text-muted uppercase tracking-wider text-[11px] mb-2 flex items-center gap-1.5">
                          <Terminal className="w-3.5 h-3.5 text-shield-accent-light" />
                          <span>Technical Evidence & Provenance</span>
                        </div>
                        <div className="p-3 rounded-lg bg-[#0C120F] border border-shield-border/70 space-y-1.5 text-shield-text-secondary">
                          {finding.evidence.map((line, idx) => (
                            <div key={idx} className="flex items-start gap-2">
                              <span className="text-shield-accent-light shrink-0">&gt;</span>
                              <span className="break-all">{line}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {finding.recommendation && (
                      <div className="p-3.5 rounded-lg bg-shield-accent/15 border border-shield-accent/30 text-shield-text-primary flex items-start gap-2.5">
                        <ArrowRight className="w-4 h-4 text-shield-accent-light shrink-0 mt-0.5" />
                        <div>
                          <strong className="text-shield-accent-light font-medium">Recommended Action: </strong>
                          <span className="text-shield-text-secondary">{finding.recommendation}</span>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
