import { useState, useCallback, useEffect } from 'react';
import type { ScanResult, ScanProgressStage, ScanStatus } from '../types/scan';
import type { ExtendedScanReport, FastPathVerdict, ScanHistoryItem } from '../types/backend';
import { scanService } from '../services/scanService';
import { validateAndNormalizeUrl } from '../utils/urlValidator';

export function useScan() {
  const [status, setStatus] = useState<ScanStatus>('idle');
  const [currentStage, setCurrentStage] = useState<ScanProgressStage | null>(null);
  const [targetUrl, setTargetUrl] = useState<string>('');
  const [hostname, setHostname] = useState<string>('');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [extendedReport, setExtendedReport] = useState<ExtendedScanReport | null>(null);
  const [fastPath, setFastPath] = useState<FastPathVerdict | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);

  // Load initial history on mount
  useEffect(() => {
    setHistory(scanService.getScanHistory());
  }, []);

  const refreshHistory = useCallback(() => {
    setHistory(scanService.getScanHistory());
  }, []);

  const startScan = useCallback(async (rawUrl: string) => {
    const validation = validateAndNormalizeUrl(rawUrl);
    if (!validation.valid) {
      setError(validation.message);
      setStatus('error');
      return;
    }

    setTargetUrl(validation.normalizedUrl);
    setHostname(validation.hostname);
    setStatus('scanning');
    setError(null);
    setResult(null);
    setExtendedReport(null);
    setFastPath(null);

    try {
      // 1. Kick off Fast-Path synchronous lane (<150ms)
      scanService
        .getFastPathVerdict(validation.normalizedUrl)
        .then((fp) => {
          setFastPath(fp);
        })
        .catch(() => {
          // Non-blocking for deep scan
        });

      // 2. Execute Deep-Scan asynchronous lane
      const scanOutput = await scanService.initiateScan(
        validation.normalizedUrl,
        (stage) => {
          setCurrentStage(stage);
        }
      );

      // 3. Fetch full extended multi-pillar report
      const extendedOutput = await scanService.getExtendedReport(validation.normalizedUrl);

      setResult(scanOutput);
      setExtendedReport(extendedOutput);
      setStatus('complete');
      refreshHistory();
    } catch (err: any) {
      setError(err?.message || 'An unexpected error occurred during model analysis.');
      setStatus('error');
    }
  }, [refreshHistory]);

  const loadHistoryItem = useCallback(async (item: ScanHistoryItem) => {
    await startScan(item.submittedUrl);
  }, [startScan]);

  const clearHistory = useCallback(() => {
    scanService.clearScanHistory();
    setHistory([]);
  }, []);

  const resetScan = useCallback(() => {
    setStatus('idle');
    setCurrentStage(null);
    setResult(null);
    setExtendedReport(null);
    setFastPath(null);
    setError(null);
  }, []);

  return {
    status,
    isScanning: status === 'scanning',
    isComplete: status === 'complete',
    isError: status === 'error',
    currentStage,
    targetUrl,
    hostname,
    result,
    extendedReport,
    fastPath,
    error,
    history,
    startScan,
    loadHistoryItem,
    clearHistory,
    resetScan,
  };
}
