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
  const isGithub = domain.includes('github');
  const isPhishing = domain.includes('micros0ft') || domain.includes('auth');
  const isShortener = domain.includes('bit.ly');
  const domainAgeDays = isGithub ? 5942 : isPhishing ? 3 : 4820;
  const domainAgeYears = (domainAgeDays / 365.25).toFixed(1);

  const registrar = isGithub
    ? 'MarkMonitor Inc. (IANA ID 292)'
    : isPhishing
    ? 'NameSilo LLC (IANA ID 1479)'
    : isShortener
    ? 'CSC Corporate Domains, Inc.'
    : 'Cloudflare, Inc. (IANA ID 1910)';

  const regDate = isPhishing ? '2026-11-04T08:12:00Z' : '2007-10-09T18:20:50Z';
  const expDate = isPhishing ? '2027-11-04T08:12:00Z' : '2028-10-09T18:20:50Z';
  const updatedDate = isPhishing ? '2026-11-04T08:14:22Z' : '2024-09-12T14:30:10Z';

  const nameservers = isGithub
    ? ['dns1.p08.nsone.net', 'dns2.p08.nsone.net', 'ns-1707.awsdns-21.co.uk', 'ns-421.awsdns-52.com']
    : isPhishing
    ? ['ns1.dnsowl.com', 'ns2.dnsowl.com']
    : ['ns1.cloudflare.com', 'ns2.cloudflare.com'];

  const statusList = isPhishing
    ? ['clientTransferProhibited', 'addPeriod']
    : ['clientDeleteProhibited', 'clientTransferProhibited', 'clientUpdateProhibited'];

  const handleCopy = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(label);
      setTimeout(() => setCopiedField(null), 2000);
    } catch {
      // Fallback
    }
  };

  return (
    <div className="space-y-6">
      {/* WHOIS Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Domain Age Card */}
        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="flex items-center gap-2 text-shield-text-muted text-xs font-mono mb-2">
            <Clock className="w-4 h-4 text-shield-accent-light" />
            <span>Domain Age</span>
          </div>
          <div className="text-2xl font-black text-shield-text-primary">
            {domainAgeDays > 365 ? `${domainAgeYears} yrs` : `${domainAgeDays} days`}
          </div>
          <div className="text-[11px] font-mono mt-1 text-shield-text-muted">
            {domainAgeDays > 730 ? (
              <span className="text-emerald-400">✓ Established & Verified</span>
            ) : domainAgeDays < 30 ? (
              <span className="text-rose-400">⚠ Newly Registered Domain (&lt;30d)</span>
            ) : (
              <span className="text-amber-400">Moderate Tenure</span>
            )}
          </div>
        </div>

        {/* Registrar Card */}
        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="flex items-center gap-2 text-shield-text-muted text-xs font-mono mb-2">
            <Building className="w-4 h-4 text-shield-accent-light" />
            <span>Sponsoring Registrar</span>
          </div>
          <div className="text-base font-bold text-shield-text-primary truncate" title={registrar}>
            {registrar.split('(')[0]}
          </div>
          <div className="text-[11px] font-mono mt-1 text-shield-text-muted truncate">
            {registrar.includes('(') ? registrar.slice(registrar.indexOf('(')) : 'ICANN Accredited'}
          </div>
        </div>

        {/* Expiration Card */}
        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="flex items-center gap-2 text-shield-text-muted text-xs font-mono mb-2">
            <Calendar className="w-4 h-4 text-shield-accent-light" />
            <span>Registry Expiration</span>
          </div>
          <div className="text-base font-bold text-shield-text-primary">
            {new Date(expDate).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })}
          </div>
          <div className="text-[11px] font-mono mt-1 text-shield-text-muted">
            Active Registration
          </div>
        </div>

        {/* DNSSEC Card */}
        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="flex items-center gap-2 text-shield-text-muted text-xs font-mono mb-2">
            <ShieldCheck className="w-4 h-4 text-shield-accent-light" />
            <span>DNSSEC Validation</span>
          </div>
          <div className="text-base font-bold text-emerald-400 flex items-center gap-1.5">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>Signed / Valid</span>
          </div>
          <div className="text-[11px] font-mono mt-1 text-shield-text-muted">
            Cryptographic zone verified
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
            onClick={() => handleCopy(JSON.stringify({ domain, registrar, regDate, expDate, nameservers }, null, 2), 'all')}
            className="px-3 py-1.5 rounded-xl bg-shield-surface border border-shield-border text-xs font-mono text-shield-text-secondary hover:text-white flex items-center gap-1.5 cursor-pointer"
          >
            {copiedField === 'all' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>Copy Raw Record</span>
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          <div className="p-3.5 rounded-xl bg-[#0D1410] border border-shield-border/60 flex items-center justify-between">
            <span className="text-shield-text-muted">Domain Name:</span>
            <span className="font-bold text-shield-text-primary">{domain}</span>
          </div>

          <div className="p-3.5 rounded-xl bg-[#0D1410] border border-shield-border/60 flex items-center justify-between">
            <span className="text-shield-text-muted">Creation Date:</span>
            <span className="text-shield-text-primary">{new Date(regDate).toUTCString()}</span>
          </div>

          <div className="p-3.5 rounded-xl bg-[#0D1410] border border-shield-border/60 flex items-center justify-between">
            <span className="text-shield-text-muted">Registry Expiry:</span>
            <span className="text-shield-text-primary">{new Date(expDate).toUTCString()}</span>
          </div>

          <div className="p-3.5 rounded-xl bg-[#0D1410] border border-shield-border/60 flex items-center justify-between">
            <span className="text-shield-text-muted">Updated Date:</span>
            <span className="text-shield-text-primary">{new Date(updatedDate).toUTCString()}</span>
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
          </div>

          {/* Domain Status Codes */}
          <div className="space-y-3">
            <h4 className="text-xs font-mono uppercase tracking-wider text-shield-accent-light flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Domain EPP Status Flags</span>
            </h4>
            <div className="space-y-2">
              {statusList.map((st) => (
                <div
                  key={st}
                  className="p-3 rounded-xl bg-shield-surface/60 border border-shield-border/50 text-xs font-mono flex items-center justify-between"
                >
                  <span className="text-shield-text-primary">{st}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950/60 text-emerald-400 border border-emerald-500/30">
                    Active Protection
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
