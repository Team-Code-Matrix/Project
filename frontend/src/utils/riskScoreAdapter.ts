import { BackendVerdict } from '../types/backend';
import { RiskLevel } from '../types/scan';

/**
 * Centered adapter bridging backend numerical risk (0 = minimal risk, 100 = maximum risk)
 * and UI trust score (100 = maximum trust, 0 = minimum trust).
 *
 * It guarantees deterministic classification across all four backend verdicts:
 * - CLEAN
 * - SUSPICIOUS
 * - MALICIOUS
 * - PKI_TRUST_COMPROMISED
 */
export class RiskScoreAdapter {
  /**
   * Converts a backend composite risk score (0-100 risk) into a UI Trust Score (0-100 trust).
   * backendRiskScore: 0 (safe) -> uiTrustScore: 100
   * backendRiskScore: 100 (lethal) -> uiTrustScore: 0
   */
  static backendRiskToUiTrustScore(backendRiskScore: number): number {
    const clamped = Math.max(0, Math.min(100, backendRiskScore));
    return 100 - clamped;
  }

  /**
   * Converts UI Trust Score (0-100 trust) to backend risk score (0-100 risk).
   */
  static uiTrustToBackendRiskScore(uiTrustScore: number): number {
    const clamped = Math.max(0, Math.min(100, uiTrustScore));
    return 100 - clamped;
  }

  /**
   * Maps a backend verdict and risk score to a UI risk level rating.
   */
  static mapVerdictToRiskLevel(verdict: BackendVerdict, backendRiskScore: number): RiskLevel {
    if (verdict === 'PKI_TRUST_COMPROMISED' || verdict === 'MALICIOUS') {
      return 'critical';
    }
    if (verdict === 'SUSPICIOUS') {
      return backendRiskScore >= 60 ? 'high' : 'caution';
    }
    // CLEAN
    return backendRiskScore > 20 ? 'caution' : 'low';
  }

  /**
   * Returns human-readable verdict title and badges.
   */
  static getVerdictPresentation(verdict: BackendVerdict): {
    label: string;
    description: string;
    badgeClass: string;
    isPkiCompromised: boolean;
  } {
    switch (verdict) {
      case 'PKI_TRUST_COMPROMISED':
        return {
          label: 'PKI Trust Compromised',
          description:
            'Cryptographic identity failure. Intermediate CA compromise, key ceremony flaw, or invalid revocation signatures detected.',
          badgeClass: 'bg-purple-950/60 text-purple-300 border-purple-500/50',
          isPkiCompromised: true,
        };
      case 'MALICIOUS':
        return {
          label: 'Confirmed Malicious',
          description:
            'Active credential harvesting, brand impersonation, or verified threat feed blacklist match.',
          badgeClass: 'bg-rose-950/60 text-rose-300 border-rose-500/50',
          isPkiCompromised: false,
        };
      case 'SUSPICIOUS':
        return {
          label: 'Suspicious / Elevated Risk',
          description:
            'Anomalous domain lifespan, unverified redirect chain, or missing security headers.',
          badgeClass: 'bg-amber-950/50 text-amber-300 border-amber-500/40',
          isPkiCompromised: false,
        };
      case 'CLEAN':
      default:
        return {
          label: 'Verified Clean',
          description:
            'No adverse indicators observed across phishing, PKI, application security, or threat feeds.',
          badgeClass: 'bg-emerald-950/50 text-emerald-300 border-emerald-500/40',
          isPkiCompromised: false,
        };
    }
  }

  /**
   * Defangs a hostile URL for safe UI presentation (e.g., https:// -> hxxps://)
   */
  static defangUrl(rawUrl: string): string {
    return rawUrl
      .replace(/^https?:\/\//i, (match) => match.toLowerCase().replace('http', 'hxxp'))
      .replace(/\./g, '[.]');
  }
}

