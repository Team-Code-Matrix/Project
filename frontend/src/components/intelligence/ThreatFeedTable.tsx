import React, { useState } from 'react';
import type { ThreatReport, ThreatCategory } from '../../types/threatIntel';
import {
  ShieldAlert,
  Search,
  CheckCircle2,
  Radio,
  PlusCircle,
} from 'lucide-react';

interface ThreatFeedTableProps {
  threats: ThreatReport[];
  onScanDomain?: (domain: string) => void;
  onOpenReportModal: () => void;
}

export const ThreatFeedTable: React.FC<ThreatFeedTableProps> = ({
  threats,
  onScanDomain,
  onOpenReportModal,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<'all' | ThreatCategory>('all');

  const filtered = threats.filter((item) => {
    const matchesSearch =
      item.domain.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (item.targetBrand && item.targetBrand.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesCat = categoryFilter === 'all' || item.category === categoryFilter;
    return matchesSearch && matchesCat;
  });

  const getStatusBadge = (status: ThreatReport['status']) => {
    switch (status) {
      case 'verified':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium bg-rose-950/50 text-rose-300 border border-rose-500/40">
            <ShieldAlert className="w-3 h-3" />
            Verified Threat
          </span>
        );
      case 'investigating':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium bg-amber-950/40 text-amber-300 border border-amber-500/30">
            <Radio className="w-3 h-3 animate-pulse" />
            Investigating
          </span>
        );
      case 'mitigated':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium bg-emerald-950/40 text-emerald-300 border border-emerald-500/30">
            <CheckCircle2 className="w-3 h-3" />
            Mitigated / Suspended
          </span>
        );
      case 'unconfirmed':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium bg-slate-900 text-slate-300 border border-slate-700">
            Unconfirmed
          </span>
        );
    }
  };

  return (
    <div className="clay-card rounded-2xl p-6 md:p-8 space-y-6 text-left">
      {/* Table Header and Actions */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-shield-border/60">
        <div>
          <div className="flex items-center gap-2.5 mb-1">
            <h3 className="text-xl font-bold text-shield-text-primary">
              Recent Threat Feed Telemetry
            </h3>
          </div>
          <p className="text-xs text-shield-text-secondary">
            Anonymized community reports and automated honey-sensor detections
          </p>
        </div>

        <button
          type="button"
          onClick={onOpenReportModal}
          className="px-4 py-2.5 rounded-xl text-xs md:text-sm font-bold text-[#080B09] bg-gradient-to-r from-[#FCE7B2] via-[#F3D081] to-[#D4A747] hover:brightness-105 active:scale-[0.98] shadow-[0_4px_16px_rgba(243,208,129,0.3)] flex items-center gap-2 self-start md:self-auto cursor-pointer transition-all"
        >
          <PlusCircle className="w-4 h-4 text-[#080B09]" />
          <span>Report Suspicious URL</span>
        </button>
      </div>

      {threats.length === 0 ? (
        <div className="py-12 text-center space-y-3">
          <div className="w-10 h-10 rounded-xl bg-[#141D18]/70 border border-[rgba(120,135,124,0.3)] text-[#F3D081] flex items-center justify-center mx-auto">
            <Radio className="w-5 h-5 text-[#F3D081]" />
          </div>
          <div className="text-sm font-mono text-[#E9E6DC]">
            Awaiting Live Threat Feed Telemetry
          </div>
          <p className="text-xs text-[#B7C4B8] max-w-sm mx-auto">
            No live threat reports currently ingested. Active incident reports and honey-sensor telemetry will stream in real time once connected.
          </p>
        </div>
      ) : (
        <>
          {/* Filter & Search Bar */}
          <div className="flex flex-col sm:flex-row items-center gap-3">
        <div className="relative flex-1 w-full flex items-center rounded-xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.3)] focus-within:border-[#F3D081]/60 px-3 py-2 text-xs font-mono">
          <Search className="w-4 h-4 text-shield-text-muted mr-2 shrink-0" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search domain, target brand, or keyword..."
            className="w-full bg-transparent text-shield-text-primary placeholder:text-shield-text-muted/60 outline-none"
          />
        </div>

        <select
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value as any)}
          className="px-3 py-2 rounded-xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.3)] text-xs font-mono text-shield-text-secondary outline-none cursor-pointer focus:border-[#F3D081]/60"
        >
          <option value="all">All Categories</option>
          <option value="impersonation">Brand Impersonation</option>
          <option value="phishing">Phishing</option>
          <option value="credential_harvesting">Credential Harvesting</option>
          <option value="crypto_drainer">Crypto Drainer</option>
          <option value="scam">Scam / Smishing</option>
          <option value="malware_distribution">Malware Distribution</option>
        </select>
      </div>

      {/* Feed Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead>
            <tr className="border-b border-shield-border/60 text-shield-text-muted uppercase tracking-wider text-[11px]">
              <th className="py-3 px-3">Reported Domain</th>
              <th className="py-3 px-3">Category</th>
              <th className="py-3 px-3">Target Brand</th>
              <th className="py-3 px-3">Status</th>
              <th className="py-3 px-3">Corroborations</th>
              <th className="py-3 px-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-shield-border/30">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-shield-text-muted">
                  No threat reports match your search query.
                </td>
              </tr>
            ) : (
              filtered.map((report) => (
                <tr
                  key={report.id}
                  className="hover:bg-white/[0.04] transition-colors"
                >
                  <td className="py-3.5 px-3 font-semibold text-shield-text-primary">
                    <div className="flex items-center gap-1.5">
                      <span className="text-rose-400">⚠</span>
                      <span className="truncate max-w-xs">{report.domain}</span>
                    </div>
                    {report.urlPath && (
                      <div className="text-[11px] text-shield-text-muted truncate max-w-xs">
                        {report.urlPath}
                      </div>
                    )}
                  </td>

                  <td className="py-3.5 px-3 text-shield-text-secondary uppercase">
                    {report.category.replace('_', ' ')}
                  </td>

                  <td className="py-3.5 px-3 text-[#F3D081]">
                    {report.targetBrand || '—'}
                  </td>

                  <td className="py-3.5 px-3">{getStatusBadge(report.status)}</td>

                  <td className="py-3.5 px-3 text-shield-text-secondary">
                    {report.corroborationCount} signals
                  </td>

                  <td className="py-3.5 px-3 text-right">
                    {onScanDomain && (
                      <button
                        type="button"
                        onClick={() => onScanDomain(`https://${report.domain}${report.urlPath || ''}`)}
                        className="px-2.5 py-1 rounded-lg text-[11px] font-mono text-[#F3D081] bg-[#141D18]/70 hover:bg-[#F3D081] hover:text-[#080B09] border border-[#F3D081]/30 transition-all cursor-pointer font-bold"
                      >
                        Inspect
                      </button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      </>
      )}
    </div>
  );
};
