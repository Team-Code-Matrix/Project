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
}

