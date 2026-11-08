import React, { useState, useEffect } from 'react';
import type { ThreatFeedMetrics, ThreatProviderStatus } from '../../types/threatIntel';
import { fetchThreatProvidersStatus } from '../../services/threatIntelService';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
} from 'recharts';
import { ShieldAlert, Users, Radio, Activity, Globe2, ShieldCheck, AlertCircle } from 'lucide-react';

interface ThreatMetricsProps {
  metrics: ThreatFeedMetrics;
}

export const ThreatMetrics: React.FC<ThreatMetricsProps> = ({ metrics }) => {
  const [providers, setProviders] = useState<ThreatProviderStatus[]>([]);

  useEffect(() => {
    fetchThreatProvidersStatus().then((list) => {
      if (list && list.length > 0) setProviders(list);
    });
  }, [metrics.totalThreatsMonitored]);
  if (!metrics || (metrics.totalThreatsMonitored === 0 && metrics.categoryBreakdown.length === 0)) {
    return (
      <div className="rounded-2xl p-8 md:p-12 text-center bg-gradient-to-br from-white/[0.04] via-[#101713]/40 to-[#080B09]/45 backdrop-blur-[3px] border border-[rgba(120,135,124,0.28)] shadow-[0_20px_50px_rgba(0,0,0,0.55)] space-y-4">
        <div className="w-12 h-12 rounded-xl bg-[#141D18]/70 border border-[rgba(120,135,124,0.3)] text-[#F3D081] flex items-center justify-center mx-auto">
          <Radio className="w-6 h-6 text-[#F3D081] animate-pulse" />
        </div>
        <div className="space-y-1.5">
          <h3 className="text-base md:text-lg font-bold font-sans uppercase tracking-tight text-[#E9E6DC]">
            Awaiting Live Telemetry Connection
          </h3>
          <p className="text-xs md:text-sm text-[#B7C4B8] max-w-md mx-auto">
            Live global threat sensors and community feeds will stream in real time once connected to the backend telemetry pipeline.
          </p>
        </div>
      </div>
    );
  }

  const chartData = metrics.categoryBreakdown.map((item) => ({
    name: item.name,
    count: item.count,
    percentage: item.percentage,
  }));

  const COLORS = ['#D97878', '#D7AA62', '#EA580C', '#79A98B', '#91A9B7', '#64756B'];

  return (
    <div className="space-y-6 text-left">
      {/* 4 Stat Metric Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="clay-card rounded-2xl p-5 border border-shield-border/70">
          <div className="flex items-center justify-between text-xs font-mono text-shield-text-muted mb-2">
            <span>Threats Monitored</span>
            <Radio className="w-4 h-4 text-shield-accent-light" />
          </div>
          <div className="text-2xl md:text-3xl font-extrabold text-shield-text-primary font-mono tabular-nums">
            {metrics.totalThreatsMonitored.toLocaleString()}
          </div>
          <div className="text-[11px] text-shield-text-muted mt-1">Live Global Sensors</div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/70">
          <div className="flex items-center justify-between text-xs font-mono text-shield-text-muted mb-2">
            <span>Active Campaigns (24h)</span>
            <Activity className="w-4 h-4 text-shield-warning" />
          </div>
          <div className="text-2xl md:text-3xl font-extrabold text-shield-warning font-mono tabular-nums">
            {metrics.activeCampaigns24h}
          </div>
          <div className="text-[11px] text-shield-text-muted mt-1">Under Active Tracking</div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/70">
          <div className="flex items-center justify-between text-xs font-mono text-shield-text-muted mb-2">
            <span>Verified Malicious</span>
            <ShieldAlert className="w-4 h-4 text-shield-danger" />
          </div>
          <div className="text-2xl md:text-3xl font-extrabold text-shield-danger font-mono tabular-nums">
            {metrics.verifiedMaliciousDomains.toLocaleString()}
          </div>
          <div className="text-[11px] text-shield-text-muted mt-1">Confirmed by Threat Intelligence</div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/70">
          <div className="flex items-center justify-between text-xs font-mono text-shield-text-muted mb-2">
            <span>Community Reports</span>
            <Users className="w-4 h-4 text-shield-accent-light" />
          </div>
          <div className="text-2xl md:text-3xl font-extrabold text-shield-accent-light font-mono tabular-nums">
            {metrics.communityReportsToday}
          </div>
          <div className="text-[11px] text-shield-text-muted mt-1">Filed by Analysts Today</div>
        </div>
      </div>

      {/* Recharts Bar Distribution Chart */}
      <div className="clay-card rounded-2xl p-6 border border-shield-border/70">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-6 gap-2">
          <div>
            <h3 className="text-base md:text-lg font-bold text-shield-text-primary">
              Observed Threat Vector Distribution
            </h3>
            <p className="text-xs text-shield-text-secondary">
              Unique Indicators of Compromise (IOCs) ingested within the last 30 days
            </p>
          </div>
        </div>

        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData} layout="vertical" margin={{ top: 5, right: 30, left: 40, bottom: 5 }}>
              <XAxis type="number" stroke="#64756B" fontSize={11} tickLine={false} />
              <YAxis
                type="category"
                dataKey="name"
                stroke="#9AA9A0"
                fontSize={11}
                tickLine={false}
                width={140}
              />
              <Tooltip
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const data = payload[0].payload;
                    return (
                      <div className="bg-[#0B100E] border border-shield-border p-2.5 rounded-lg text-xs font-mono shadow-xl">
                        <div className="font-semibold text-shield-text-primary">{data.name}</div>
                        <div className="text-shield-accent-light mt-0.5">
                          {data.count} reported domains ({data.percentage}%)
                        </div>
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <Bar dataKey="count" radius={[0, 6, 6, 0]}>
                {chartData.map((_, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 8 Global Threat Intelligence Providers Transparency Grid */}
      {providers.length > 0 && (
        <div className="clay-card rounded-2xl p-6 border border-shield-border/70 space-y-4">
          <div>
            <h3 className="text-base md:text-lg font-bold text-shield-text-primary">
              Federated Threat Intelligence Providers (Source Transparency)
            </h3>
            <p className="text-xs text-shield-text-secondary">
              Real-time synchronization status and API connectivity across official external cybersecurity intelligence feeds
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
            {providers.map((p) => (
              <div
                key={p.providerId}
                className="p-3.5 rounded-xl bg-[#080B09]/60 backdrop-blur-[2px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/40 transition-all space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-shield-text-primary uppercase text-[11px] truncate">
                    {p.providerId.replace('_', ' ')}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      p.status === 'ONLINE' || p.status === 'CONNECTED'
                        ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/30'
                        : p.status === 'SYNCING'
                        ? 'bg-sky-950/80 text-sky-400 border border-sky-500/30 animate-pulse'
                        : p.status === 'NOT_CONFIGURED'
                        ? 'bg-amber-950/60 text-amber-300 border border-amber-500/30'
                        : p.status === 'DEGRADED' || p.status === 'RATE_LIMITED'
                        ? 'bg-yellow-950/60 text-yellow-300 border border-yellow-500/30'
                        : p.status === 'STALE'
                        ? 'bg-orange-950/60 text-orange-300 border border-orange-500/30'
                        : 'bg-rose-950/60 text-rose-300 border border-rose-500/30'
                    }`}
                  >
                    {p.status.replace('_', ' ')}
                  </span>
                </div>
                <div className="text-[10px] text-shield-text-muted truncate">
                  {p.providerName}
                </div>
                <div className="text-[10px] text-shield-text-secondary pt-1 border-t border-shield-border/30 flex items-center justify-between">
                  <span>Ingested: <strong>{p.recordsIngestedTotal}</strong></span>
                  <span className="truncate max-w-[110px]" title={p.lastSyncTime || 'Pending'}>
                    {p.lastSyncTime ? new Date(p.lastSyncTime).toLocaleTimeString() : (p.isConfigured ? 'Pending' : 'No API Key')}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
