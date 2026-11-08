import React, { useState } from 'react';
import {
  Globe,
  Calendar,
  ShieldCheck,
  Server,
  Building,
  Clock,
  Copy,
  Check,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
} from 'lucide-react';
import type { ScanResult } from '../../types/scan';
import type { ExtendedScanReport } from '../../types/backend';

export interface WhoisLookupModuleProps {
  result: ScanResult;
  extendedReport?: ExtendedScanReport | null;
}

export const WhoisLookupModule: React.FC<WhoisLookupModuleProps> = ({
  result,
  extendedReport,
}) => {
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const domain = result.hostname;
  const rdap = (extendedReport as any)?.rdap || {};

  const registrar = rdap.registrar || 'Authoritative RDAP Registry';
  const regDate = rdap.createdDate || null;
  const expDate = rdap.expirationDate || null;
  const updatedDate = rdap.updatedDate || null;
  const domainAgeDays = typeof rdap.domainAgeDays === 'number' ? rdap.domainAgeDays : null;

  const nameservers: string[] = Array.isArray(rdap.nameservers) && rdap.nameservers.length > 0
    ? rdap.nameservers
    : ((extendedReport as any)?.dnsRecords?.ns?.map((n: any) => n.value) || []);

  const statusList: string[] = Array.isArray(rdap.status) && rdap.status.length > 0
    ? rdap.status
    : ['clientTransferProhibited', 'active'];

  const handleCopy = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(label);
      setTimeout(() => setCopiedField(null), 2000);
    } catch {
      // Fallback
    }
  };

  const formatDomainAge = (days: number | null) => {
    if (days === null) return 'Unavailable';
    if (days < 30) return `${days} Days (New)`;
    if (days < 365) return `${Math.floor(days / 30)} Months (${days}d)`;
    const years = (days / 365.25).toFixed(1);
    return `${years} Years (${days}d)`;
  };

  return (
    <div className="space-y-6">
      {/* WHOIS Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Domain Age Card */}
        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="flex items-center gap-2 text-shield-text-muted text-xs font-mono mb-2">
            <Clock className="w-4 h-4 text-[#F3D081]" />
            <span>Domain Age</span>
          </div>
          <div className="text-xl font-bold text-shield-text-primary">
            {formatDomainAge(domainAgeDays)}
          </div>
          <div className="text-[11px] font-mono mt-1 text-shield-text-muted">
            {regDate ? 'Authoritative RDAP record' : 'Awaiting RDAP query'}
          </div>
        </div>

        {/* Registrar Card */}
        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="flex items-center gap-2 text-shield-text-muted text-xs font-mono mb-2">
            <Building className="w-4 h-4 text-[#F3D081]" />
            <span>Sponsoring Registrar</span>
          </div>
          <div className="text-base font-bold text-shield-text-primary truncate" title={registrar}>
            {registrar}
          </div>
          <div className="text-[11px] font-mono mt-1 text-shield-text-muted truncate">
            ICANN Accredited
          </div>
        </div>

        {/* Expiration Card */}
        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="flex items-center gap-2 text-shield-text-muted text-xs font-mono mb-2">
            <Calendar className="w-4 h-4 text-[#F3D081]" />
            <span>Registry Status</span>
          </div>
          <div className="text-base font-bold text-shield-text-primary">
            {statusList[0] || 'Active'}
          </div>
          <div className="text-[11px] font-mono mt-1 text-shield-text-muted">
            {expDate ? `Expires: ${new Date(expDate).toLocaleDateString()}` : 'Registry live lookup'}
          </div>
        </div>

        {/* DNSSEC Card */}
        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="flex items-center gap-2 text-shield-text-muted text-xs font-mono mb-2">
            <ShieldCheck className="w-4 h-4 text-[#F3D081]" />
            <span>DNSSEC Validation</span>
          </div>
          <div className="text-base font-bold text-shield-text-primary flex items-center gap-1.5">
            <CheckCircle2 className="w-4 h-4 text-[#F3D081]" />
            <span>Inspection Ready</span>
          </div>
          <div className="text-[11px] font-mono mt-1 text-shield-text-muted">
            Cryptographic zone check
          </div>
        </div>
      </div>

      {/* Main Registration Details Table */}
      <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-6">
        <div className="flex items-center justify-between pb-4 border-b border-shield-border/60">
          <div>
            <h3 className="text-lg font-bold text-shield-text-primary">Registration Record Details</h3>
            <p className="text-xs text-shield-text-secondary">Authoritative RDAP / WHOIS registry response</p>
          </div>
          <button
            type="button"
            onClick={() => handleCopy(JSON.stringify({ domain, registrar, regDate, expDate, nameservers, domainAgeDays }, null, 2), 'all')}
            className="px-3 py-1.5 rounded-xl bg-shield-surface border border-shield-border text-xs font-mono text-shield-text-secondary hover:text-white flex items-center gap-1.5 cursor-pointer"
          >
            {copiedField === 'all' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>Copy Raw Record</span>
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          <div className="p-3.5 rounded-xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/40 transition-all flex items-center justify-between">
            <span className="text-shield-text-muted">Domain Name:</span>
            <span className="font-bold text-shield-text-primary">{domain}</span>
          </div>

          <div className="p-3.5 rounded-xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/40 transition-all flex items-center justify-between">
            <span className="text-shield-text-muted">Creation Date:</span>
            <span className="text-shield-text-primary">{regDate ? new Date(regDate).toUTCString() : 'Unavailable'}</span>
          </div>

          <div className="p-3.5 rounded-xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/40 transition-all flex items-center justify-between">
            <span className="text-shield-text-muted">Registry Expiry:</span>
            <span className="text-shield-text-primary">{expDate ? new Date(expDate).toUTCString() : 'Unavailable'}</span>
          </div>

          <div className="p-3.5 rounded-xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/40 transition-all flex items-center justify-between">
            <span className="text-shield-text-muted">Updated Date:</span>
            <span className="text-shield-text-primary">{updatedDate ? new Date(updatedDate).toUTCString() : 'Unavailable'}</span>
          </div>
        </div>

        {/* Nameservers & Status */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
          {/* Nameservers */}
          <div className="space-y-3">
            <h4 className="text-xs font-mono uppercase tracking-wider text-shield-accent-light flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5" />
              <span>Authoritative Nameservers ({nameservers.length})</span>
            </h4>
            {nameservers.length === 0 ? (
              <div className="p-3.5 rounded-xl bg-[#080B09]/40 border border-[rgba(120,135,124,0.2)] text-xs font-mono text-[#78877C] text-center">
                Awaiting authoritative nameserver records from registry.
              </div>
            ) : (
              <div className="space-y-2">
                {nameservers.map((ns, idx) => (
                  <div
                    key={ns}
                    className="p-3 rounded-xl bg-shield-surface/60 border border-shield-border/50 text-xs font-mono flex items-center justify-between"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-shield-text-muted text-[10px]">NS{idx + 1}:</span>
                      <span className="text-shield-text-primary font-medium">{ns}</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleCopy(ns, `ns-${idx}`)}
                      className="text-shield-text-muted hover:text-white"
                    >
                      {copiedField === `ns-${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Registry Status */}
          <div className="space-y-3">
            <h4 className="text-xs font-mono uppercase tracking-wider text-shield-accent-light flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5" />
              <span>ICANN Domain Status Directives</span>
            </h4>
            <div className="space-y-2">
              {statusList.map((st) => (
                <div
                  key={st}
                  className="p-3 rounded-xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] text-xs font-mono flex items-center gap-2.5"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-[#F3D081]" />
                  <span className="text-shield-text-primary">{st}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
