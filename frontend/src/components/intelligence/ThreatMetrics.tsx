import React from 'react';
import type { ThreatFeedMetrics } from '../../types/threatIntel';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
} from 'recharts';
import { ShieldAlert, Users, Radio, Activity } from 'lucide-react';

interface ThreatMetricsProps {
  metrics: ThreatFeedMetrics;
}

export const ThreatMetrics: React.FC<ThreatMetricsProps> = ({ metrics }) => {
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
          <div className="text-[11px] text-shield-text-muted mt-1">Takedown Notices Sent</div>
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
              Relative frequency of identified malicious schemes over the last 30 days
            </p>
          </div>
          <span className="text-[11px] font-mono text-shield-text-muted bg-shield-surface-elevated px-2.5 py-1 rounded-md border border-shield-border self-start sm:self-auto">
            Sample Telemetry
          </span>
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
    </div>
  );
};
