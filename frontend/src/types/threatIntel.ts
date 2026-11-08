export type ThreatCategory =
  | 'phishing'
  | 'impersonation'
  | 'credential_harvesting'
  | 'malware_distribution'
  | 'scam'
  | 'suspicious_redirect'
  | 'crypto_drainer';

export type ReportStatus = 'verified' | 'investigating' | 'mitigated' | 'unconfirmed';

export interface ThreatReport {
  id: string;
  domain: string;
  urlPath?: string;
  category: ThreatCategory;
  reportedAt: string;
  status: ReportStatus;
  confidenceScore: number;
  reporterType: 'community' | 'automated_sensor' | 'partner_feed';
  corroborationCount: number;
  targetBrand?: string;
  indicators: string[];
  provider?: string;
  country?: string;
  sourceUrl?: string;
}

export interface ThreatProviderStatus {
  providerId: string;
  providerName: string;
  status: 'CONNECTED' | 'ONLINE' | 'SYNCING' | 'NOT_CONFIGURED' | 'RATE_LIMITED' | 'DEGRADED' | 'DISCONNECTED' | 'STALE' | 'ERROR';
  lastSyncTime?: string | null;
  lastError?: string | null;
  recordsIngestedTotal: number;
  recordsLastSync: number;
  updateIntervalSec: number;
  requiresApiKey: boolean;
  isConfigured: boolean;
  description?: string;
}

export interface ThreatSubmissionPayload {
  url: string;
  category: ThreatCategory;
  notes?: string;
  targetBrand?: string;
  hasInteracted: boolean;
}

export interface ThreatFeedMetrics {
  totalThreatsMonitored: number;
  activeCampaigns24h: number;
  verifiedMaliciousDomains: number;
  communityReportsToday: number;
  categoryBreakdown: {
    category: ThreatCategory;
    name: string;
    count: number;
    percentage: number;
  }[];
  providerBreakdown?: {
    provider: string;
    count: number;
  }[];
  geoDistribution?: {
    country: string;
    count: number;
  }[];
}

