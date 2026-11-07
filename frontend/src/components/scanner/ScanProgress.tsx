import React from 'react';
import type { ScanProgressStage } from '../../types/scan';
import { SCAN_STAGES } from '../../services/scanService';
import { Loader2, CheckCircle2, Terminal } from 'lucide-react';

interface ScanProgressProps {
  currentStage: ScanProgressStage | null;
  targetUrl: string;
  hostname: string;
}

export const ScanProgress: React.FC<ScanProgressProps> = ({
  currentStage,
  targetUrl,
  hostname,
}) => {
  const currentStageIndex = SCAN_STAGES.findIndex(
    (s) => s.id === currentStage?.id
  );

  return (
    <div className="clay-card rounded-2xl p-6 md:p-8 max-w-3xl mx-auto w-full border border-[rgba(120,135,124,0.3)] shadow-[0_20px_50px_rgba(0,0,0,0.55)] my-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-shield-border/60 gap-4">
        <div className="flex items-center gap-3">
          <div className="relative p-2.5 rounded-xl bg-[#F3D081]/15 border border-[#F3D081]/30 text-[#F3D081]">
            <Loader2 className="w-5 h-5 animate-spin text-[#F3D081]" />
          </div>
          <div className="text-left">
            <div className="flex items-center gap-2">
              <h3 className="text-lg font-bold text-shield-text-primary">
                Multi-Model Security Assessment in Progress
              </h3>
            </div>
            <div className="text-xs font-mono text-shield-text-secondary truncate max-w-md mt-0.5">
              Target: <span className="text-[#F3D081]">{hostname}</span> ({targetUrl})
            </div>
          </div>
        </div>

        <div className="text-xs font-mono text-shield-text-secondary px-3 py-1.5 rounded-lg bg-[#080B09]/60 backdrop-blur-[2px] border border-[rgba(120,135,124,0.3)] self-start sm:self-auto">
          STAGE {Math.max(1, currentStageIndex + 1)} / {SCAN_STAGES.length}
        </div>
      </div>

      {/* Stages Pipeline List */}
      <div className="py-6 space-y-3.5">
        {SCAN_STAGES.map((stage, idx) => {
          const isDone = currentStageIndex > idx;
          const isCurrent = currentStageIndex === idx;
          const isUpcoming = currentStageIndex < idx;

          return (
            <div
              key={stage.id}
              className={`flex items-center justify-between p-3 rounded-xl border transition-all text-xs md:text-sm font-medium ${
                isCurrent
                  ? 'bg-[#101713]/60 backdrop-blur-[2px] border-[#F3D081]/50 text-shield-text-primary shadow-[0_0_15px_rgba(243,208,129,0.12)]'
                  : isDone
                  ? 'bg-shield-surface/40 border-shield-border/40 text-shield-text-secondary'
                  : 'bg-transparent border-transparent opacity-40 text-shield-text-muted'
              }`}
            >
              <div className="flex items-center gap-3">
                <div className="w-6 h-6 rounded-full flex items-center justify-center shrink-0">
                  {isDone ? (
                    <CheckCircle2 className="w-5 h-5 text-shield-success" />
                  ) : isCurrent ? (
                    <Loader2 className="w-4 h-4 animate-spin text-[#F3D081]" />
                  ) : (
                    <span className="w-2 h-2 rounded-full bg-shield-border" />
                  )}
                </div>
                <span>{stage.label}</span>
              </div>

              <div className="font-mono text-xs hidden sm:block">
                {isDone && <span className="text-shield-success">COMPLETE</span>}
                {isCurrent && <span className="text-[#F3D081] animate-pulse">EVALUATING</span>}
                {isUpcoming && <span className="text-shield-text-muted">QUEUED</span>}
              </div>
            </div>
          );
        })}
      </div>

      {/* Real-time telemetry log feed */}
      <div className="bg-[#080B09]/70 backdrop-blur-[3px] rounded-xl p-4 border border-[rgba(120,135,124,0.3)] font-mono text-xs text-left">
        <div className="flex items-center justify-between text-shield-text-secondary border-b border-shield-border/40 pb-2 mb-2.5">
          <span className="flex items-center gap-2">
            <Terminal className="w-3.5 h-3.5 text-[#F3D081]" />
            <span>SANDBOX TELEMETRY LOG</span>
          </span>
          <span className="text-[10px] text-[#F3D081] flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#F3D081] animate-ping" />
            STREAMING
          </span>
        </div>
        <div className="text-shield-text-secondary space-y-1">
          <p className="text-[#F3D081] font-mono">
            &gt; {currentStage?.logSnippet || 'Initialising isolated sandboxed network evaluation...'}
          </p>
          <p className="text-shield-text-muted text-[11px]">
            &gt; Enforcing non-invasive read-only policy. No client-side browser connections initiated.
          </p>
        </div>
      </div>
    </div>
  );
};
