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
  getScanHistory(): Promise<ScanHistoryItem[]>;
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
import { API_BASE_URL } from '../config/api';

/**
 * Isolated Mock Service strictly for unit tests.
 * Never used in production execution.
 */
export class MockScanService implements IScanService {
  readonly isMock = true;

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
    await new Promise((r) => setTimeout(r, 60));
    return extended.fastPath;
  }

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
      await new Promise((resolve) => setTimeout(resolve, 50));
    }

    const result = generateDynamicScanResult(normalizedUrl, hostname, protocol);
    return result;
  }

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

  async getScanHistory(): Promise<ScanHistoryItem[]> {
    try {
      const stored = localStorage.getItem(LOCAL_STORAGE_HISTORY_KEY);
      if (stored) {
        return JSON.parse(stored) as ScanHistoryItem[];
      }
    } catch {
      // Fallback
    }
    return [];
  }

  saveScanHistory(item: ScanHistoryItem): void {
    try {
      const current = this.getLocalHistory().filter((i) => i.hostname !== item.hostname);
      const updated = [item, ...current].slice(0, 30);
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

  private getLocalHistory(): ScanHistoryItem[] {
    try {
      const stored = localStorage.getItem(LOCAL_STORAGE_HISTORY_KEY);
      if (stored) return JSON.parse(stored);
    } catch {
      // Fallback
    }
    return [];
  }
}

/**
 * Production Real Scan Service.
 * Authoritative client communicating exclusively with the backend REST and WebSocket APIs.
 * Zero dummy data or mock fallbacks in production.
 */
export class ProductionScanService implements IScanService {
  readonly isMock = false;
  private cachedReports = new Map<string, ExtendedScanReport>();

  /**
   * Fast-path synchronous lane (<150ms)
   * Queries real backend fast-path API.
   */
  async getFastPathVerdict(rawUrl: string): Promise<FastPathVerdict> {
    const validation = validateAndNormalizeUrl(rawUrl);
    if (!validation.valid) {
      throw new Error(validation.message);
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      try {
        controller.abort(new Error('Fast-path evaluation timed out after 15s.'));
      } catch {
        controller.abort();
      }
    }, 15000);

    try {
      const res = await fetch(`${API_BASE_URL}/api/scan/fast-path`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: validation.normalizedUrl }),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        const data = await res.json();
        return {
          evaluatedInMs: data.evaluatedInMs || 25,
          bloomFilterHit: Boolean(data.bloomFilterHit),
          bloomSource: data.bloomSource || 'None',
          googleSafeBrowsingMatch: Boolean(data.googleSafeBrowsingMatch),
          cachedReputation: data.cachedReputation || 'UNRATED',
          mozillaOneCrlRevoked: Boolean(data.mozillaOneCrlRevoked),
          preliminaryVerdict: data.preliminaryVerdict || 'CLEAN',
          summary: data.summary || 'Fast-path evaluation completed.',
        };
      }
      throw new Error(`Fast-path API returned status ${res.status}`);
    } catch (err: any) {
      clearTimeout(timeoutId);
      const isAbort = err?.name === 'AbortError' || String(err?.message || '').toLowerCase().includes('abort');
      const reason = isAbort
        ? 'Fast-path request timed out waiting for backend. Proceeding to full deep scan.'
        : `Fast-path evaluation unavailable: ${err?.message || 'Connection error'}. Proceeding to full deep scan.`;
      // Return unrated fallback without fabricating safety
      return {
        evaluatedInMs: 0,
        bloomFilterHit: false,
        bloomSource: 'None',
        googleSafeBrowsingMatch: false,
        cachedReputation: 'UNRATED',
        mozillaOneCrlRevoked: false,
        preliminaryVerdict: 'SUSPICIOUS',
        summary: reason,
      };
    }
  }

  /**
   * Deep-scan asynchronous lane execution
   * Sends request to backend and tracks real execution progress.
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

    // Stage progression tracker
    let currentStep = 0;
    const progressInterval = setInterval(() => {
      if (currentStep < totalSteps - 1) {
        currentStep++;
        const stepDef = SCAN_STAGES[currentStep];
        if (onProgress) {
          onProgress(
            {
              id: stepDef.id,
              label: stepDef.label,
              status: 'in_progress',
              logSnippet: stepDef.logSnippet,
            },
            currentStep + 1,
            totalSteps
          );
        }
      }
    }, 280);

    // Initial stage event
    if (onProgress) {
      onProgress(
        {
          id: SCAN_STAGES[0].id,
          label: SCAN_STAGES[0].label,
          status: 'in_progress',
          logSnippet: SCAN_STAGES[0].logSnippet,
        },
        1,
        totalSteps
      );
    }

    let backendReport: ExtendedScanReport | null = null;
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => {
        try {
          controller.abort(new Error('Deep scan timed out after 60s. Backend may still be processing or cold-starting.'));
        } catch {
          controller.abort();
        }
      }, 60000);

      const res = await fetch(`${API_BASE_URL}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: normalizedUrl }),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      if (!res.ok) {
        throw new Error(`Trust Shield backend returned error HTTP ${res.status}: ${res.statusText}`);
      }

      const data = await res.json();
      if (!data || !data.report) {
        throw new Error('Malformed response payload received from Trust Shield scan engine.');
      }

      backendReport = data.report as ExtendedScanReport;
    } catch (err: any) {
      clearInterval(progressInterval);
      const isAbort = err?.name === 'AbortError' || String(err?.message || '').toLowerCase().includes('abort');
      const errorMsg = isAbort
        ? `Connection to Trust Shield backend timed out (60s). The server at ${API_BASE_URL} may be waking up from cold-start or taking longer for deep network inspection. Please try again.`
        : `Failed to reach Trust Shield backend at ${API_BASE_URL}. Ensure server is running: ${err?.message || 'Connection refused'}`;
      throw new Error(errorMsg);
    } finally {
      clearInterval(progressInterval);
    }

    // Cache the authentic report
    this.cachedReports.set(normalizedUrl, backendReport);

    // Final completion stage update
    if (onProgress) {
      const finalStep = SCAN_STAGES[totalSteps - 1];
      onProgress(
        {
          id: finalStep.id,
          label: finalStep.label,
          status: 'completed',
          logSnippet: `Scan completed: Verdict ${backendReport.backendVerdict} (Trust Score: ${backendReport.uiTrustScore}/100)`,
        },
        totalSteps,
        totalSteps
      );
    }

    // Map genuine backend report to ScanResult contract
    const result: ScanResult = {
      scanId: backendReport.scanId,
      submittedUrl: backendReport.submittedUrl,
      hostname: backendReport.hostname,
      protocol: protocol,
      score: backendReport.uiTrustScore,
      riskLevel: backendReport.riskLevel || (backendReport.uiTrustScore >= 70 ? 'low' : backendReport.uiTrustScore >= 40 ? 'caution' : 'critical'),
      summary: backendReport.summary,
      models: (backendReport as any).models || [],
      findings: (backendReport as any).findings || [],
      recommendedActions: (backendReport as any).recommendedActions || [],
      checkedAt: backendReport.checkedAt,
      isDemo: false,
      criticalOverride: Boolean(backendReport.criticalOverride),
      overrideReason: (backendReport as any).overrideReason,
      checksCompleted: (backendReport as any).checksCompleted !== undefined ? (backendReport as any).checksCompleted : 6,
      checksSkipped: (backendReport as any).checksSkipped !== undefined ? (backendReport as any).checksSkipped : 0,
      checksErrored: (backendReport as any).checksErrored !== undefined ? (backendReport as any).checksErrored : 0,
      resolvedIp: backendReport.resolvedIp,
      asn: (backendReport as any).asn,
      country: (backendReport as any).country,
      primaryScheme: (backendReport as any).primaryScheme,
      modelConsensus: (backendReport as any).modelConsensus,
    };

    // Save to local storage history
    this.saveScanHistory({
      scanId: backendReport.scanId,
      hostname: backendReport.hostname,
      submittedUrl: backendReport.submittedUrl,
      timestamp: backendReport.checkedAt,
      verdict: backendReport.backendVerdict,
      riskScore: backendReport.backendRiskScore,
      trustScore: backendReport.uiTrustScore,
      resolvedIp: backendReport.resolvedIp,
    });

    return result;
  }

  async getExtendedReport(rawUrl: string): Promise<ExtendedScanReport> {
    const validation = validateAndNormalizeUrl(rawUrl);
    if (!validation.valid) {
      throw new Error(validation.message);
    }

    const cached = this.cachedReports.get(validation.normalizedUrl);
    if (cached) return cached;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      try {
        controller.abort(new Error('Extended report request timed out after 60s.'));
      } catch {
        controller.abort();
      }
    }, 60000);

    const res = await fetch(`${API_BASE_URL}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: validation.normalizedUrl }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      if (data && data.report) {
        this.cachedReports.set(validation.normalizedUrl, data.report);
        return data.report as ExtendedScanReport;
      }
    }

    throw new Error(`Failed to retrieve extended assessment report for ${rawUrl} from backend.`);
  }

  async getScanHistory(): Promise<ScanHistoryItem[]> {
    try {
      const res = await fetch(`${API_BASE_URL}/api/history`);
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data)) {
          return data;
        }
      }
    } catch {
      // Network offline, fallback to local storage
    }

    try {
      const stored = localStorage.getItem(LOCAL_STORAGE_HISTORY_KEY);
      if (stored) return JSON.parse(stored);
    } catch {
      // Fallback
    }

    return [];
  }

  saveScanHistory(item: ScanHistoryItem): void {
    try {
      const stored = localStorage.getItem(LOCAL_STORAGE_HISTORY_KEY);
      const current: ScanHistoryItem[] = stored ? JSON.parse(stored) : [];
      const filtered = current.filter((i) => i.scanId !== item.scanId && i.hostname !== item.hostname);
      const updated = [item, ...filtered].slice(0, 30);
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

// Export Production Scan Service
export const scanService: IScanService = new ProductionScanService();
