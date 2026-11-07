import type { ThreatReport, ThreatFeedMetrics } from '../types/threatIntel';

/**
 * Initial threat feed telemetry state.
 * Empty by default — populated dynamically by backend threat intelligence feeds.
 */
export const INITIAL_THREAT_FEED: ThreatReport[] = [];

/**
 * Initial threat feed metrics state.
 * Empty / zeroed by default — populated dynamically by backend telemetry sensors.
 */
export const THREAT_FEED_METRICS: ThreatFeedMetrics = {
  totalThreatsMonitored: 0,
  activeCampaigns24h: 0,
  verifiedMaliciousDomains: 0,
  communityReportsToday: 0,
  categoryBreakdown: [],
};
