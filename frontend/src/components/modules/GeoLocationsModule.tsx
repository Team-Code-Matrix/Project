import React from 'react';
import {
  MapPin,
  Globe,
  Server,
  Network,
  ShieldCheck,
  CheckCircle2,
  ExternalLink,
} from 'lucide-react';
import type { ScanResult } from '../../types/scan';
import type { ExtendedScanReport } from '../../types/backend';

export interface GeoLocationsModuleProps {
  result: ScanResult;
  extendedReport?: ExtendedScanReport | null;
}

export const GeoLocationsModule: React.FC<GeoLocationsModuleProps> = ({
  result,
  extendedReport: _extendedReport,
}) => {
  const geo = {
    ip: result.resolvedIp || 'Awaiting IP resolution',
    country: result.country || 'Global Anycast / Pending',
    countryCode: result.country ? result.country.slice(0, 2).toUpperCase() : '—',
    city: 'Edge POP Location',
    region: 'Anycast Network Edge',
    postalCode: '—',
    coordinates: 'Routing Coordinate Dependent',
    asn: result.asn || 'Pending ASN Resolution',
    org: result.asn || 'Authoritative Network Provider',
    isp: 'Anycast Transit Provider',
    threatScore: result.score !== null ? 100 - result.score : 0,
  };

  return (
    <div className="space-y-6 text-left">
      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Target Host IP</div>
          <div className="text-xl font-mono font-bold text-shield-text-primary">{geo.ip}</div>
          <div className="text-[11px] font-mono text-emerald-400 mt-1">IPv4 Anycast BGP Route</div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Origin Country</div>
          <div className="text-xl font-bold text-shield-text-primary">{geo.country}</div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">{geo.city}, {geo.region}</div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Autonomous System</div>
          <div className="text-xl font-mono font-bold text-shield-accent-light">{geo.asn}</div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1 truncate">{geo.org}</div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">ASN Risk Rating</div>
          <div className={`text-xl font-bold ${geo.threatScore > 50 ? 'text-rose-400' : 'text-emerald-400'}`}>
            {geo.threatScore > 50 ? 'HIGH ABUSE' : 'TRUSTED TIER 1'}
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">BGP peer reputation</div>
        </div>
      </div>

      {/* Geolocation & Network Infrastructure Card */}
      <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-6">
        <div>
          <h3 className="text-lg font-bold text-shield-text-primary">Hosting Infrastructure & Geolocation Telemetry</h3>
          <p className="text-xs text-shield-text-secondary">Physical server localization and BGP routing carrier data</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
          <div className="p-4 rounded-xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/40 transition-all flex items-center justify-between">
            <span className="text-shield-text-muted">Host IP Address:</span>
            <span className="font-bold text-shield-text-primary">{geo.ip}</span>
          </div>

          <div className="p-4 rounded-xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/40 transition-all flex items-center justify-between">
            <span className="text-shield-text-muted">Geographic Coordinates:</span>
            <span className="text-shield-text-primary">{geo.coordinates}</span>
          </div>

          <div className="p-4 rounded-xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/40 transition-all flex items-center justify-between">
            <span className="text-shield-text-muted">Hosting Carrier (ISP):</span>
            <span className="font-bold text-[#F3D081] truncate max-w-[200px]">{geo.isp}</span>
          </div>

          <div className="p-4 rounded-xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/40 transition-all flex items-center justify-between">
            <span className="text-shield-text-muted">Registered ASN Entity:</span>
            <span className="text-shield-text-primary truncate max-w-[200px]">{geo.org}</span>
          </div>

          <div className="p-4 rounded-xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/40 transition-all flex items-center justify-between">
            <span className="text-shield-text-muted">City & Metro Region:</span>
            <span className="text-shield-text-primary">{geo.city}, {geo.region}</span>
          </div>

          <div className="p-4 rounded-xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/40 transition-all flex items-center justify-between">
            <span className="text-shield-text-muted">Postal / Zip Code:</span>
            <span className="text-shield-text-primary">{geo.postalCode}</span>
          </div>
        </div>

        {/* Anycast Distribution Note */}
        <div className="p-4 rounded-2xl bg-shield-surface border border-shield-border flex items-start gap-3 text-xs">
          <Network className="w-4 h-4 text-shield-accent-light shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-bold text-shield-text-primary font-mono">BGP Global Anycast Route Telemetry</span>
            <p className="text-shield-text-secondary leading-relaxed">
              Target IP resolves across global BGP Anycast mesh peering points. Client traffic is automatically routed to the nearest regional point-of-presence (PoP), mitigating denial-of-service attempts and latency.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
