export type RiskLevel =
  | 'low'
  | 'caution'
  | 'high'
  | 'critical'
  | 'insufficient_data';

export type ModelVerdict =
  | 'clear'
  | 'suspicious'
  | 'malicious'
  | 'unknown'
  | 'error'
  | 'skipped';

export type FindingSeverity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'informational';

export type ScanStatus = 'idle' | 'scanning' | 'complete' | 'error';

export interface ModelMetric {
  label: string;
  value: string | number;
  state?: 'normal' | 'warn' | 'alert';
}

export interface ModelResult {
  id: string;
  number: string;
  name: string;
  category: string;
  description: string;
  verdict: ModelVerdict;
  confidence?: number; // 0 - 100 percentage
  summary: string;
  evidence: string[];
  metrics?: ModelMetric[];
  checkedAt?: string;
  status: 'completed' | 'skipped' | 'error';
  executionTimeMs?: number;
}

export interface Finding {
  id: string;
  title: string;
  severity: FindingSeverity;
  description: string;
  source: string;
  evidence?: string[];
  recommendation?: string;
  cveReference?: string;
}

export interface RecommendedAction {
  id: string;
  level: 'essential' | 'advisory' | 'monitoring';
  title: string;
  detail: string;
  targetUser: 'general' | 'admin' | 'all';
}

export interface ScanResult {
  scanId: string;
  submittedUrl: string;
  hostname: string;
  punycodeHostname?: string;
  protocol: 'https:' | 'http:';
  score: number | null;
  riskLevel: RiskLevel;
  summary: string;
  models: ModelResult[];
  findings: Finding[];
  recommendedActions: RecommendedAction[];
  checkedAt: string;
  isDemo: boolean;
  criticalOverride: boolean;
  overrideReason?: string;
  checksCompleted: number;
  checksSkipped: number;
  checksErrored: number;
  resolvedIp?: string;
  asn?: string;
  country?: string;
  primaryScheme?: string;
  modelConsensus?: string;
}

export interface ScanProgressStage {
  id: string;
  label: string;
  status: 'pending' | 'in_progress' | 'completed' | 'error';
  logSnippet?: string;
}

