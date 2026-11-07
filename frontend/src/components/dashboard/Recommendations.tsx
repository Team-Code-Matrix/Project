import React from 'react';
import type { RecommendedAction, RiskLevel } from '../../types/scan';
import { AlertOctagon, Shield } from 'lucide-react';

interface RecommendationsProps {
  actions: RecommendedAction[];
  riskLevel: RiskLevel;
  onOpenReportModal?: () => void;
}

export const Recommendations: React.FC<RecommendationsProps> = ({
  actions,
  riskLevel,
  onOpenReportModal,
}) => {
  const isHighRiskOrCritical = riskLevel === 'high' || riskLevel === 'critical';

  return (
    <div className="clay-card rounded-2xl p-6 md:p-8 space-y-6 text-left">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-6 border-b border-shield-border/60">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-shield-accent/20 border border-shield-accent/30 text-shield-accent-light">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-xl md:text-2xl font-bold text-shield-text-primary">
              Recommended Protective Actions
            </h2>
            <p className="text-xs text-shield-text-secondary">
              Practical guidance tailored to the observed threat profile
            </p>
          </div>
        </div>

        {isHighRiskOrCritical && onOpenReportModal && (
          <button
            type="button"
            onClick={onOpenReportModal}
            className="clay-button-secondary px-3.5 py-2 rounded-xl text-xs font-mono text-shield-danger hover:text-white border-shield-danger/40 flex items-center gap-2 self-start sm:self-auto cursor-pointer"
          >
            <AlertOctagon className="w-3.5 h-3.5" />
            <span>Submit Community Threat Report</span>
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {actions.map((act) => {
          const isEssential = act.level === 'essential';

          return (
            <div
              key={act.id}
              className={`p-4 rounded-xl border flex flex-col justify-between ${
                isEssential
                  ? 'bg-rose-950/20 border-rose-500/40 text-shield-text-primary'
                  : 'bg-shield-surface-elevated/60 border-shield-border/70 text-shield-text-secondary'
              }`}
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span
                    className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border ${
                      isEssential
                        ? 'bg-rose-950/60 text-rose-300 border-rose-500/40'
                        : 'bg-shield-surface text-shield-accent-light border-shield-border'
                    }`}
                  >
                    {act.level}
                  </span>
                  <span className="text-[11px] font-mono text-shield-text-muted">
                    Target: {act.targetUser}
                  </span>
                </div>

                <h4 className="text-sm md:text-base font-bold text-shield-text-primary mb-1">
                  {act.title}
                </h4>

                <p className="text-xs leading-relaxed text-shield-text-secondary">
                  {act.detail}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
