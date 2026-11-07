import React from 'react';
import {
  History,
  Clock,
  ExternalLink,
  Trash2,
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
} from 'lucide-react';
import type { ScanHistoryItem } from '../../types/backend';
import { RiskBadge } from '../shared/RiskBadge';

export interface ScanHistoryModuleProps {
  history: ScanHistoryItem[];
  onSelectScan: (item: ScanHistoryItem) => void;
  onClearHistory: () => void;
}

export const ScanHistoryModule: React.FC<ScanHistoryModuleProps> = ({
  history,
  onSelectScan,
  onClearHistory,
}) => {
  return (
    <div className="space-y-6 text-left">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-[#0D1410] border border-shield-border/80">
        <div>
          <span className="text-xs font-mono text-shield-accent-light uppercase tracking-wider">
            Assessment Session Ledger
          </span>
          <h2 className="text-lg md:text-xl font-bold text-shield-text-primary">
            Historical Scan Registry ({history.length})
          </h2>
        </div>

        {history.length > 0 && (
          <button
            type="button"
            onClick={onClearHistory}
            className="px-3.5 py-2 rounded-xl bg-shield-surface border border-shield-border hover:border-rose-500/50 text-xs font-mono text-rose-400 flex items-center gap-2 cursor-pointer transition-colors self-start sm:self-auto"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear History</span>
          </button>
        )}
      </div>

      {/* History Ledger Table */}
      <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-4">
        {history.length === 0 ? (
          <div className="py-12 text-center text-xs font-mono text-shield-text-muted space-y-2">
            <History className="w-8 h-8 text-shield-text-muted/50 mx-auto" />
            <p>No historical scans recorded yet.</p>
            <p className="text-[11px]">Assess any target URL to populate your personal audit ledger.</p>
          </div>
        ) : (
          <div className="space-y-3 font-mono text-xs">
            {history.map((item) => (
              <div
                key={item.scanId}
                className="p-4 rounded-2xl bg-[#0D1410] border border-shield-border/60 hover:border-shield-accent/50 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 group"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2.5">
                    <span className="font-bold text-sm text-shield-text-primary group-hover:text-shield-accent-light transition-colors">
                      {item.hostname}
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-shield-surface text-shield-text-muted border border-shield-border">
                      {item.scanId}
                    </span>
                  </div>
                  <div className="text-[11px] text-shield-text-muted truncate max-w-md">
                    {item.submittedUrl}
                  </div>
                  <div className="text-[10px] text-shield-text-muted flex items-center gap-2 pt-0.5">
                    <Clock className="w-3 h-3 text-shield-accent-light" />
                    <span>{new Date(item.timestamp).toLocaleString()}</span>
                    {item.resolvedIp && <span>• IP: {item.resolvedIp}</span>}
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <div className="text-right">
                    <div className="text-sm font-black text-shield-text-primary">
                      {item.trustScore} / 100
                    </div>
                    <span
                      className={`text-[10px] font-bold ${
                        item.verdict === 'CLEAN'
                          ? 'text-emerald-400'
                          : item.verdict === 'SUSPICIOUS'
                          ? 'text-amber-400'
                          : 'text-rose-400'
                      }`}
                    >
                      {item.verdict}
                    </span>
                  </div>

                  <button
                    type="button"
                    onClick={() => onSelectScan(item)}
                    className="px-3.5 py-2 rounded-xl bg-shield-surface border border-shield-border group-hover:border-emerald-500/50 group-hover:bg-emerald-950/40 text-xs font-mono text-shield-text-primary group-hover:text-emerald-400 flex items-center gap-1.5 transition-all cursor-pointer"
                  >
                    <span>Load Report</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

