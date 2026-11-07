import { describe, it, expect } from 'vitest';
import { MockScanService, SCAN_STAGES } from './scanService';

describe('MockScanService', () => {
  it('correctly stages progress and returns 94 for github.com', async () => {
    const service = new MockScanService();
    const recordedStages: string[] = [];

    const result = await service.initiateScan('https://github.com', (stage) => {
      recordedStages.push(stage.id);
    });

    expect(recordedStages).toEqual(SCAN_STAGES.map((s) => s.id));
    expect(result.score).toBe(94);
    expect(result.riskLevel).toBe('low');
    expect(result.models.length).toBe(6);
    expect(result.criticalOverride).toBe(false);
  });

  it('triggers critical override for phishing harvester domain', async () => {
    const service = new MockScanService();
    const result = await service.initiateScan('https://login.micros0ft-support-auth.com/verify');

    expect(result.criticalOverride).toBe(true);
    expect(result.riskLevel).toBe('critical');
    expect(result.score).toBe(14);
    expect(result.overrideReason).toContain('CRITICAL SECURITY THREAT DETECTED');
    expect(result.findings.some((f) => f.severity === 'critical')).toBe(true);
  });

  it('flags multi-hop shortener as high risk', async () => {
    const service = new MockScanService();
    const result = await service.initiateScan('https://bit.ly/secure-account-verify-302');

    expect(result.riskLevel).toBe('high');
    expect(result.score).toBe(38);
    expect(result.models.find((m) => m.id === 'm-redirect')?.verdict).toBe('malicious');
  });

  it('flags expired certificate as caution', async () => {
    const service = new MockScanService();
    const result = await service.initiateScan('https://expired-tls.untrusted-cdn-assets.org');

    expect(result.riskLevel).toBe('caution');
    expect(result.score).toBe(62);
    expect(result.models.find((m) => m.id === 'm-tls')?.verdict).toBe('suspicious');
  });
});

