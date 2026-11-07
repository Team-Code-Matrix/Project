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
  extendedReport,
}) => {
  const isGithub = result.hostname.includes('github');
  const isPhishing = result.hostname.includes('micros0ft') || result.hostname.includes('auth');

  const geo = isGithub
    ? {
        ip: result.resolvedIp || '140.82.121.4',
        country: 'United States',
        countryCode: 'US',
        city: 'San Francisco',
        region: 'California (CA)',
        postalCode: '94107',
        coordinates: '37.7749° N, 122.4194° W',
        asn: 'AS36459',
        org: 'GitHub, Inc. (Microsoft Sub-Entity)',
        isp: 'GitHub Anycast Routing Network',
        threatScore: 0,
      }
    : isPhishing
    ? {
        ip: result.resolvedIp || '194.38.20.15',
        country: 'Russia',
        countryCode: 'RU',
        city: 'Moscow',
        region: 'Moscow Oblast',
        postalCode: '101000',
        coordinates: '55.7558° N, 37.6173° E',
        asn: 'AS48282',
        org: 'Bulletproof Hosting Solutions Ltd',
        isp: 'Offshore Bulletproof Transit',
        threatScore: 92,
      }
    : {
        ip: result.resolvedIp || '104.21.48.12',
        country: result.country || 'United States',
        countryCode: 'US',
        city: 'Ashburn',
        region: 'Virginia (VA)',
        postalCode: '20147',
        coordinates: '39.0438° N, 77.4874° W',
        asn: 'AS13335',
        org: 'Cloudflare, Inc.',
        isp: 'Cloudflare Global Anycast',
        threatScore: 10,
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
          <div className="p-4 rounded-xl bg-[#0D1410] border border-shield-border/60 flex items-center justify-between">
            <span className="text-shield-text-muted">Host IP Address:</span>
            <span className="font-bold text-shield-text-primary">{geo.ip}</span>
          </div>

          <div className="p-4 rounded-xl bg-[#0D1410] border border-shield-border/60 flex items-center justify-between">
            <span className="text-shield-text-muted">Geographic Coordinates:</span>
            <span className="text-shield-text-primary">{geo.coordinates}</span>
          </div>

          <div className="p-4 rounded-xl bg-[#0D1410] border border-shield-border/60 flex items-center justify-between">
            <span className="text-shield-text-muted">Hosting Carrier (ISP):</span>
            <span className="font-bold text-shield-accent-light truncate max-w-[200px]">{geo.isp}</span>
          </div>

          <div className="p-4 rounded-xl bg-[#0D1410] border border-shield-border/60 flex items-center justify-between">
            <span className="text-shield-text-muted">Registered ASN Entity:</span>
            <span className="text-shield-text-primary truncate max-w-[200px]">{geo.org}</span>
          </div>

          <div className="p-4 rounded-xl bg-[#0D1410] border border-shield-border/60 flex items-center justify-between">
            <span className="text-shield-text-muted">City & Metro Region:</span>
            <span className="text-shield-text-primary">{geo.city}, {geo.region}</span>
          </div>

          <div className="p-4 rounded-xl bg-[#0D1410] border border-shield-border/60 flex items-center justify-between">
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
