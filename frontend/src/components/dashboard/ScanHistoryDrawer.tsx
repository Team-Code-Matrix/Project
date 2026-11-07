import React from 'react';
import type { ScanHistoryItem } from '../../types/backend';
import { RiskScoreAdapter } from '../../utils/riskScoreAdapter';
import { History, X, Clock, Trash2, ArrowUpRight, Shield } from 'lucide-react';

interface ScanHistoryDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  history: ScanHistoryItem[];
  onSelectScan: (item: ScanHistoryItem) => void;
  onClearHistory: () => void;
}

export const ScanHistoryDrawer: React.FC<ScanHistoryDrawerProps> = ({
  isOpen,
  onClose,
  history,
  onSelectScan,
  onClearHistory,
}) => {
  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/80 backdrop-blur-md animate-fadeIn"
      role="dialog"
      aria-modal="true"
    >
      <div className="w-full max-w-md h-full bg-[#0B100E]/92 backdrop-blur-2xl border-l border-white/[0.08] shadow-2xl p-6 flex flex-col justify-between text-left font-mono">
        {/* Drawer Header */}
        <div className="space-y-4">
          <div className="flex items-center justify-between pb-4 border-b border-shield-border/60">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-shield-accent/20 border border-shield-accent/30 text-shield-accent-light">
                <History className="w-4 h-4 text-shield-accent-light" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-shield-text-primary">
                  Scan History
                </h3>
                <span className="text-[11px] text-shield-text-muted">
                  {history.length} assessment records
                </span>
              </div>
            </div>

            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-lg text-shield-text-muted hover:text-shield-text-primary hover:bg-shield-surface"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Records List */}
          <div className="overflow-y-auto max-h-[calc(100vh-180px)] space-y-2.5 pr-1">
            {history.length === 0 ? (
              <div className="py-16 text-center text-xs text-shield-text-muted space-y-2">
                <Shield className="w-8 h-8 text-shield-border mx-auto" />
                <p>No recent scans saved.</p>
                <p className="text-[11px]">Submitted domains will appear here for instant recall.</p>
              </div>
            ) : (
              history.map((item) => {
                const { label, badgeClass } = RiskScoreAdapter.getVerdictPresentation(item.verdict);
                return (
                  <div
                    key={item.scanId}
                    onClick={() => {
                      onSelectScan(item);
                      onClose();
                    }}
                    className="p-3.5 rounded-xl bg-shield-surface border border-shield-border/60 hover:bg-shield-surface-elevated hover:border-shield-accent/50 transition-all cursor-pointer group flex flex-col justify-between"
                  >
                    <div className="flex items-start justify-between gap-2 mb-1.5">
                      <span className="text-xs font-bold text-shield-text-primary group-hover:text-shield-accent-light truncate max-w-[200px]">
                        {item.hostname}
                      </span>
                      <span className="text-xs font-bold font-sans text-shield-accent-light">
                        {item.trustScore}/100
                      </span>
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-shield-text-muted mt-2 pt-2 border-t border-shield-border/30">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3 text-shield-accent-light" />
                        {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${badgeClass}`}>
                        {label}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Drawer Footer Actions */}
        {history.length > 0 && (
          <div className="pt-4 border-t border-shield-border/60 flex items-center justify-between text-xs">
            <button
              type="button"
              onClick={onClearHistory}
              className="text-rose-400 hover:text-rose-300 flex items-center gap-1.5 cursor-pointer"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear History</span>
            </button>
            <span className="text-shield-text-muted text-[11px]">Stored locally in session</span>
          </div>
        )}
      </div>
    </div>
  );
};

