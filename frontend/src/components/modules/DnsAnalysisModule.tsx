import React, { useState } from 'react';
import {
  Network,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  Server,
  Mail,
  FileText,
  Key,
} from 'lucide-react';
import type { ScanResult } from '../../types/scan';
import type { ExtendedScanReport } from '../../types/backend';

export interface DnsAnalysisModuleProps {
  result: ScanResult;
  extendedReport?: ExtendedScanReport | null;
}

export const DnsAnalysisModule: React.FC<DnsAnalysisModuleProps> = ({
  result,
  extendedReport,
}) => {
  const [activeTab, setActiveTab] = useState<'all' | 'a' | 'mx' | 'txt' | 'soa'>('all');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const domain = result.hostname;
  const ip = result.resolvedIp;
  const dns = extendedReport?.dnsRecords;

  const aRecords = dns?.a && dns.a.length > 0
    ? dns.a
    : (ip && ip !== 'Unresolved (NXDOMAIN)' ? [{ type: 'A', name: domain, value: ip, ttl: 300 }] : []);

  const aaaaRecords = dns?.aaaa || [];
  const mxRecords = dns?.mx || [];
  const nsRecords = dns?.ns || [];

  const txtRecords = (dns?.txt || []).map((t: any) => {
    let key = 'TXT RECORD';
    const val = t.value || '';
    if (val.toLowerCase().includes('v=spf1')) key = 'SPF POLICY';
    else if (val.toLowerCase().includes('v=dmarc1')) key = 'DMARC POLICY';
    else if (val.toLowerCase().includes('google-site-verification')) key = 'GOOGLE VERIFICATION';
    else if (val.toLowerCase().includes('domainkey')) key = 'DKIM POLICY';
    else if (t.name?.includes('_dmarc')) key = 'DMARC RECORD';
    return {
      type: 'TXT',
      key,
      value: val,
      ttl: t.ttl || 300,
    };
  });

  const soaRecord = dns?.soa || null;

  const records = {
    a: aRecords,
    aaaa: aaaaRecords,
    mx: mxRecords,
    ns: nsRecords,
    txt: txtRecords,
    soa: soaRecord,
  };

  const handleCopy = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(id);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch {
      // Fallback
    }
  };

  return (
    <div className="space-y-6">
      {/* Top DNS Summary Badges */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-left">
        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">A Address Record</div>
          <div className="text-xl font-mono font-bold text-shield-text-primary truncate">
            {records.a[0]?.value || (ip && ip !== 'Unresolved (NXDOMAIN)' ? ip : 'Pending Resolution')}
          </div>
          <div className="text-[11px] font-mono text-[#F3D081] mt-1 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" />
            {records.a.length > 0 ? `${records.a.length} IPv4 Resolved` : (ip ? 'IPv4 Resolved' : 'Awaiting Query')}
          </div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">DNSSEC Security</div>
          <div className="text-xl font-bold text-shield-text-primary flex items-center gap-1.5">
            <ShieldCheck className="w-5 h-5 text-[#F3D081]" />
            <span>{dns?.dnssec ? 'Active' : (records.a.length > 0 ? 'Standard DNS' : 'Inspection Ready')}</span>
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">
            {dns?.dnssec ? 'RRSIG validated' : (records.a.length > 0 ? 'Unsigned zone' : 'Awaiting RRSIG verification')}
          </div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">DMARC Protection</div>
          <div className="text-xl font-bold text-shield-text-primary">
            {records.txt.some(t => t.key.includes('DMARC')) ? 'DMARC Active' : (records.txt.some(t => t.key.includes('SPF')) ? 'SPF Active' : (dns ? 'Not Configured' : 'Pending TXT Query'))}
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">
            {records.txt.some(t => t.key.includes('DMARC')) ? 'p=reject/quarantine policy' : 'SPF / DMARC verification'}
          </div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Authoritative NS</div>
          <div className="text-xl font-bold text-shield-text-primary">
            {records.ns.length} Nameservers
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1 truncate">
            {records.ns[0]?.value || 'Awaiting NS resolution'}
          </div>
        </div>
      </div>

      {/* Main DNS Zone Records View */}
      <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-shield-border/60">
          <div>
            <h3 className="text-lg font-bold text-shield-text-primary">DNS Zone Resource Records</h3>
            <p className="text-xs text-shield-text-secondary">Authoritative zone query results</p>
          </div>

          <div className="flex items-center gap-1.5 p-1 rounded-xl bg-shield-surface-elevated border border-shield-border text-xs font-mono">
            {(['all', 'a', 'mx', 'txt', 'soa'] as const).map((tab) => (
              <button
                key={tab}
                type="button"
                onClick={() => setActiveTab(tab)}
                className={`px-3 py-1 rounded-lg uppercase transition-colors cursor-pointer ${
                  activeTab === tab ? 'bg-shield-accent text-white font-bold' : 'text-shield-text-secondary'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
        </div>

        {/* A and AAAA Records */}
        {(activeTab === 'all' || activeTab === 'a') && (
          <div className="space-y-3">
            <h4 className="text-xs font-mono uppercase tracking-wider text-shield-accent-light flex items-center gap-1.5">
              <Network className="w-3.5 h-3.5" />
              <span>Host Address Records (A / AAAA)</span>
            </h4>
            <div className="space-y-2">
              {[...records.a, ...records.aaaa].map((rec, i) => (
                <div
                  key={i}
                  className="p-3.5 rounded-xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/40 transition-all flex items-center justify-between text-xs font-mono"
                >
                  <div className="flex items-center gap-3">
                    <span className="px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 font-bold border border-emerald-500/30">
                      {rec.type}
                    </span>
                    <span className="text-shield-text-primary font-bold">{rec.value}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-shield-text-muted text-[11px]">TTL: {rec.ttl}s</span>
                    <button
                      type="button"
                      onClick={() => handleCopy(rec.value, `a-${i}`)}
                      className="text-shield-text-muted hover:text-white"
                    >
                      {copiedKey === `a-${i}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* MX Mail Records */}
        {(activeTab === 'all' || activeTab === 'mx') && (
          <div className="space-y-3 pt-2">
            <h4 className="text-xs font-mono uppercase tracking-wider text-shield-accent-light flex items-center gap-1.5">
              <Mail className="w-3.5 h-3.5" />
              <span>Mail Exchange Records (MX)</span>
            </h4>
            {records.mx.length === 0 ? (
              <div className="p-4 rounded-xl bg-[#080B09]/40 border border-[rgba(120,135,124,0.2)] text-xs font-mono text-[#78877C] text-center">
                No MX records configured or awaiting backend DNS query.
              </div>
            ) : (
              <div className="space-y-2">
                {records.mx.map((rec, i) => (
                  <div
                    key={i}
                    className="p-3.5 rounded-xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/40 transition-all flex items-center justify-between text-xs font-mono"
                  >
                    <div className="flex items-center gap-3">
                      <span className="px-2 py-0.5 rounded bg-purple-950/80 text-purple-400 font-bold border border-purple-500/30">
                        MX (Pref {rec.priority})
                      </span>
                      <span className="text-shield-text-primary font-bold">{rec.value}</span>
                    </div>
                    <span className="text-shield-text-muted text-[11px]">TTL: {rec.ttl}s</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* TXT Records (SPF / DMARC) */}
        {(activeTab === 'all' || activeTab === 'txt') && (
          <div className="space-y-3 pt-2">
            <h4 className="text-xs font-mono uppercase tracking-wider text-shield-accent-light flex items-center gap-1.5">
              <FileText className="w-3.5 h-3.5" />
              <span>Text & Policy Records (TXT / SPF / DMARC)</span>
            </h4>
            {records.txt.length === 0 ? (
              <div className="p-4 rounded-xl bg-[#080B09]/40 border border-[rgba(120,135,124,0.2)] text-xs font-mono text-[#78877C] text-center">
                No TXT records returned or awaiting SPF/DMARC query from backend.
              </div>
            ) : (
              <div className="space-y-2">
                {records.txt.map((rec, i) => (
                  <div
                    key={i}
                    className="p-3.5 rounded-xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/40 transition-all space-y-1.5 text-xs font-mono"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[#F3D081] font-bold text-[11px] uppercase">
                        {rec.key}
                      </span>
                      <button
                        type="button"
                        onClick={() => handleCopy(rec.value, `txt-${i}`)}
                        className="text-shield-text-muted hover:text-white flex items-center gap-1 text-[11px]"
                      >
                        {copiedKey === `txt-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>Copy</span>
                      </button>
                    </div>
                    <div className="p-2 rounded bg-black/40 text-shield-text-secondary break-all">
                      {rec.value}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* SOA Record */}
        {(activeTab === 'all' || activeTab === 'soa') && (
          <div className="space-y-3 pt-2">
            <h4 className="text-xs font-mono uppercase tracking-wider text-shield-accent-light flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5" />
              <span>Start of Authority (SOA)</span>
            </h4>
            {records.soa ? (
              <div className="p-4 rounded-xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/40 transition-all grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                <div>
                  <div className="text-shield-text-muted text-[10px]">Primary Nameserver</div>
                  <div className="font-bold text-shield-text-primary mt-0.5 truncate">{records.soa.primaryNs}</div>
                </div>
                <div>
                  <div className="text-shield-text-muted text-[10px]">Hostmaster</div>
                  <div className="font-bold text-shield-text-primary mt-0.5 truncate">{records.soa.hostmaster}</div>
                </div>
                <div>
                  <div className="text-shield-text-muted text-[10px]">Serial Number</div>
                  <div className="font-bold text-shield-accent-light mt-0.5">{records.soa.serial}</div>
                </div>
                <div>
                  <div className="text-shield-text-muted text-[10px]">Refresh / Retry</div>
                  <div className="text-shield-text-primary mt-0.5">{records.soa.refresh}s / {records.soa.retry}s</div>
                </div>
              </div>
            ) : (
              <div className="p-4 rounded-xl bg-[#080B09]/40 border border-[rgba(120,135,124,0.2)] text-xs font-mono text-[#78877C] text-center">
                Awaiting authoritative SOA zone query from backend DNS resolver.
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
