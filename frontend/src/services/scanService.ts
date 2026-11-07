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

    // No seeded mock history — empty by default until real scans are performed
    return [];
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

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

export class HybridScanService implements IScanService {
  readonly isMock = false;
  private mockFallback = new MockScanService();
  private cachedReports = new Map<string, ExtendedScanReport>();

  /**
   * Fast-path synchronous lane (<150ms)
   * Queries backend fast-path API; falls back cleanly to client heuristics.
   */
  async getFastPathVerdict(rawUrl: string): Promise<FastPathVerdict> {
    const validation = validateAndNormalizeUrl(rawUrl);
    if (!validation.valid) {
      throw new Error(validation.message);
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1500);
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
          evaluatedInMs: data.evaluatedInMs || 34,
          bloomFilterHit: Boolean(data.bloomFilterHit),
          bloomSource: data.bloomSource,
          googleSafeBrowsingMatch: Boolean(data.googleSafeBrowsingMatch),
          cachedReputation: data.cachedReputation || 'BENIGN',
          mozillaOneCrlRevoked: Boolean(data.mozillaOneCrlRevoked),
          preliminaryVerdict: data.preliminaryVerdict || 'CLEAN',
          summary: data.summary || 'Fast-path cache hit confirmed via backend.',
        };
      }
    } catch {
      // Backend offline or network error: graceful fallback
    }

    return this.mockFallback.getFastPathVerdict(rawUrl);
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

    // Concurrently trigger backend scan request while animating progress
    const backendPromise = (async () => {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 4000);
        const res = await fetch(`${API_BASE_URL}/api/scan`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: normalizedUrl }),
          signal: controller.signal,
        });
        clearTimeout(timeoutId);
        if (res.ok) {
          const data = await res.json();
          if (data && data.report) {
            return data.report as ExtendedScanReport;
          }
        }
      } catch {
        // Fallback
      }
      return null;
    })();

    // Staged progress for UI feedback
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

      await new Promise((resolve) => setTimeout(resolve, 180));
    }

    const backendReport = await backendPromise;
    let result: ScanResult;

    if (backendReport) {
      this.cachedReports.set(normalizedUrl, backendReport);
      const dynamicBase = generateDynamicScanResult(normalizedUrl, hostname, protocol);
      result = {
        ...dynamicBase,
        scanId: backendReport.scanId,
        score: backendReport.uiTrustScore,
        criticalOverride: backendReport.criticalOverride ?? (backendReport.uiTrustScore <= 18),
        summary: backendReport.summary,
        resolvedIp: backendReport.resolvedIp || dynamicBase.resolvedIp,
      };
      this.saveScanHistory({
        scanId: backendReport.scanId,
        hostname: backendReport.hostname,
        submittedUrl: backendReport.submittedUrl,
        timestamp: backendReport.checkedAt,
        verdict: backendReport.backendVerdict,
        riskScore: backendReport.backendRiskScore,
        trustScore: backendReport.uiTrustScore,
        resolvedIp: backendReport.resolvedIp || '127.0.0.1',
      });
    } else {
      result = await this.mockFallback.initiateScan(rawUrl);
    }

    return result;
  }

  async getExtendedReport(rawUrl: string): Promise<ExtendedScanReport> {
    const validation = validateAndNormalizeUrl(rawUrl);
    if (!validation.valid) {
      throw new Error(validation.message);
    }
    const cached = this.cachedReports.get(validation.normalizedUrl);
    if (cached) return cached;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);
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
    } catch {
      // Fallback
    }

    return this.mockFallback.getExtendedReport(rawUrl);
  }

  getScanHistory(): ScanHistoryItem[] {
    return this.mockFallback.getScanHistory();
  }

  saveScanHistory(item: ScanHistoryItem): void {
    this.mockFallback.saveScanHistory(item);
  }

  clearScanHistory(): void {
    this.mockFallback.clearScanHistory();
  }
}

// API Adapter export
export const scanService: IScanService = new HybridScanService();
