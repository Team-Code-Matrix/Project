import type { ScanResult, ScanProgressStage } from '../types/scan';
import type { ExtendedScanReport, FastPathVerdict, ScanHistoryItem } from '../types/backend';
import { validateAndNormalizeUrl } from '../utils/urlValidator';
import { generateDynamicScanResult } from './mockScanData';
import { generateDynamicExtendedReport } from './extendedMockData';
import { scanWebSocketService } from './websocketService';

export interface IScanService {
  isMock: boolean;
  initiateScan(
    rawUrl: string,
    onProgress?: (stage: ScanProgressStage, stepIndex: number, totalSteps: number) => void
  ): Promise<ScanResult>;
  getFastPathVerdict(rawUrl: string): Promise<FastPathVerdict>;
  getExtendedReport(rawUrl: string): Promise<ExtendedScanReport>;
  getScanHistory(): ScanHistoryItem[];
  saveScanHistory(item: ScanHistoryItem): void;
  clearScanHistory(): void;
}

export const SCAN_STAGES: { id: string; label: string; logSnippet: string }[] = [
  {
    id: 'parse',
    label: 'Parsing URL structure & domain hierarchy',
    logSnippet: 'RFC-3986 syntax normalized. Protocol and path tokens decomposed.',
  },
  {
    id: 'domain_intel',
    label: 'Analysing domain intelligence & WHOIS telemetry',
    logSnippet: 'DNS A/AAAA records verified. Autonomous System and registrar parsed.',
  },
  {
    id: 'phishing_check',
    label: 'Checking phishing indicators & impersonation patterns',
    logSnippet: 'DOM similarity analysis and visual credential-intake scan running.',
  },
  {
    id: 'tls_validation',
    label: 'Reviewing TLS certificate signals & chain integrity',
    logSnippet: 'Verifying X.509 chain against root trust store, checking SCT logs.',
  },
  {
    id: 'redirect_monitor',
    label: 'Analysing redirect behaviour & destination hops',
    logSnippet: 'Tracing HTTP 3xx hops. Mapping autonomous system cross-boundary transitions.',
  },
  {
    id: 'posture_eval',
    label: 'Assessing web security posture & header hygiene',
    logSnippet: 'Inspecting HSTS, CSP, XFO, and cookie samesite attributes.',
  },
  {
    id: 'correlation',
    label: 'Correlating signals & computing Trust Score',
    logSnippet: 'Multi-model correlation matrix completed. Verdict assembled.',
  },
];

const LOCAL_STORAGE_HISTORY_KEY = 'trust_shield_scan_history_v1';

export class MockScanService implements IScanService {
  readonly isMock = true;

  /**
   * Fast-path synchronous lane (<150ms)
   */
  async getFastPathVerdict(rawUrl: string): Promise<FastPathVerdict> {
    const validation = validateAndNormalizeUrl(rawUrl);
    if (!validation.valid) {
      throw new Error(validation.message);
    }
    const extended = generateDynamicExtendedReport(
      validation.normalizedUrl,
      validation.hostname,
      validation.protocol
    );
    // Simulate fast <150ms turnaround
    await new Promise((r) => setTimeout(r, 60));
    return extended.fastPath;
  }

  /**
   * Deep-scan asynchronous lane execution
   */
  async initiateScan(
    rawUrl: string,
    onProgress?: (stage: ScanProgressStage, stepIndex: number, totalSteps: number) => void
  ): Promise<ScanResult> {
    const validation = validateAndNormalizeUrl(rawUrl);

    if (!validation.valid) {
      throw new Error(validation.message);
    }

    const { normalizedUrl, hostname, protocol } = validation;
    const totalSteps = SCAN_STAGES.length;

    // Simulate staged progress
    for (let i = 0; i < totalSteps; i++) {
      const stepDef = SCAN_STAGES[i];
      if (onProgress) {
        onProgress(
          {
            id: stepDef.id,
            label: stepDef.label,
            status: 'in_progress',
            logSnippet: stepDef.logSnippet,
          },
          i + 1,
          totalSteps
        );
      }

      // Stream event through WebSocket bus
      scanWebSocketService.dispatchMockEvent({
        scanId: 'active-scan',
        eventType: 'WORKER_PROGRESS',
        workerId: 'phishing_detonation',
        workerName: stepDef.label,
        status: 'running',
        progressPercentage: Math.round(((i + 1) / totalSteps) * 100),
        snippet: stepDef.logSnippet,
        timestamp: new Date().toISOString(),
      });

      // 200ms delay per stage to show smooth progression
      await new Promise((resolve) => setTimeout(resolve, 200));
    }

    const result = generateDynamicScanResult(normalizedUrl, hostname, protocol);

    // Save to scan history
    const extended = generateDynamicExtendedReport(normalizedUrl, hostname, protocol);
    this.saveScanHistory({
      scanId: result.scanId,
      hostname: result.hostname,
      submittedUrl: result.submittedUrl,
      timestamp: result.checkedAt,
      verdict: extended.backendVerdict,
      riskScore: extended.backendRiskScore,
      trustScore: result.score ?? 50,
      resolvedIp: result.resolvedIp,
    });

    return result;
  }

  /**
   * Retrieves extended multi-pillar telemetry
   */
  async getExtendedReport(rawUrl: string): Promise<ExtendedScanReport> {
    const validation = validateAndNormalizeUrl(rawUrl);
    if (!validation.valid) {
      throw new Error(validation.message);
    }
    return generateDynamicExtendedReport(
      validation.normalizedUrl,
      validation.hostname,
      validation.protocol
    );
  }

  /**
   * Scan history management with session/localStorage
   */
  getScanHistory(): ScanHistoryItem[] {
    try {
      const stored = localStorage.getItem(LOCAL_STORAGE_HISTORY_KEY);
      if (stored) {
        return JSON.parse(stored) as ScanHistoryItem[];
      }
    } catch {
      // Fallback
    }

    // Default seeded history
    return [
      {
        scanId: 'scn_gh_982410a7',
        hostname: 'github.com',
        submittedUrl: 'https://github.com',
        timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
        verdict: 'CLEAN',
        riskScore: 6,
        trustScore: 94,
        resolvedIp: '140.82.121.4',
      },
      {
        scanId: 'scn_phish_3914bc82',
        hostname: 'login.micros0ft-support-auth.com',
        submittedUrl: 'https://login.micros0ft-support-auth.com/verify',
        timestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
        verdict: 'MALICIOUS',
        riskScore: 86,
        trustScore: 14,
        resolvedIp: '185.220.101.45',
      },
      {
        scanId: 'scn_cert_182944b1',
        hostname: 'expired-tls.untrusted-cdn-assets.org',
        submittedUrl: 'https://expired-tls.untrusted-cdn-assets.org',
        timestamp: new Date(Date.now() - 1000 * 60 * 240).toISOString(),
        verdict: 'PKI_TRUST_COMPROMISED',
        riskScore: 92,
        trustScore: 8,
        resolvedIp: '198.51.100.89',
      },
    ];
  }

  saveScanHistory(item: ScanHistoryItem): void {
    try {
      const current = this.getScanHistory().filter((i) => i.hostname !== item.hostname);
      const updated = [item, ...current].slice(0, 20); // Keep 20 recent
      localStorage.setItem(LOCAL_STORAGE_HISTORY_KEY, JSON.stringify(updated));
    } catch {
      // Fallback
    }
  }

  clearScanHistory(): void {
    try {
      localStorage.removeItem(LOCAL_STORAGE_HISTORY_KEY);
    } catch {
      // Fallback
    }
  }
}

// API Adapter export
export const scanService: IScanService = new MockScanService();
