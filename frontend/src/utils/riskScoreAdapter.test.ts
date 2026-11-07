import { describe, it, expect } from 'vitest';
import { RiskScoreAdapter } from './riskScoreAdapter';

describe('RiskScoreAdapter', () => {
  it('converts backend risk score to UI trust score correctly', () => {
    expect(RiskScoreAdapter.backendRiskToUiTrustScore(0)).toBe(100);
    expect(RiskScoreAdapter.backendRiskToUiTrustScore(6)).toBe(94);
    expect(RiskScoreAdapter.backendRiskToUiTrustScore(86)).toBe(14);
    expect(RiskScoreAdapter.backendRiskToUiTrustScore(92)).toBe(8);
    expect(RiskScoreAdapter.backendRiskToUiTrustScore(100)).toBe(0);
  });

  it('clamps out-of-range risk values safely', () => {
    expect(RiskScoreAdapter.backendRiskToUiTrustScore(-10)).toBe(100);
    expect(RiskScoreAdapter.backendRiskToUiTrustScore(150)).toBe(0);
  });

  it('maps verdicts to expected risk levels', () => {
    expect(RiskScoreAdapter.mapVerdictToRiskLevel('CLEAN', 6)).toBe('low');
    expect(RiskScoreAdapter.mapVerdictToRiskLevel('SUSPICIOUS', 45)).toBe('caution');
    expect(RiskScoreAdapter.mapVerdictToRiskLevel('SUSPICIOUS', 70)).toBe('high');
    expect(RiskScoreAdapter.mapVerdictToRiskLevel('MALICIOUS', 86)).toBe('critical');
    expect(RiskScoreAdapter.mapVerdictToRiskLevel('PKI_TRUST_COMPROMISED', 92)).toBe('critical');
  });

  it('correctly defangs hostile URLs', () => {
    expect(RiskScoreAdapter.defangUrl('https://evil-phish.net/verify')).toBe(
      'hxxps://evil-phish[.]net/verify'
    );
    expect(RiskScoreAdapter.defangUrl('http://185.220.101.45/dump')).toBe(
      'hxxp://185[.]220[.]101[.]45/dump'
    );
  });
});

