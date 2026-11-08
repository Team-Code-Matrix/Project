import type {
  ThreatReport,
  ThreatFeedMetrics,
  ThreatSubmissionPayload,
  ThreatProviderStatus,
} from '../types/threatIntel';
import { API_BASE_URL } from '../config/api';

export const EMPTY_TELEMETRY_METRICS: ThreatFeedMetrics = {
  totalThreatsMonitored: 0,
  activeCampaigns24h: 0,
  verifiedMaliciousDomains: 0,
  communityReportsToday: 0,
  categoryBreakdown: [],
  providerBreakdown: [],
  geoDistribution: [],
};

export async function fetchLiveThreatsAndMetrics(): Promise<{
  threats: ThreatReport[];
  metrics: ThreatFeedMetrics;
}> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000);
    const res = await fetch(`${API_BASE_URL}/api/threats`, { signal: controller.signal });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      const rawThreats = Array.isArray(data.threats) ? data.threats : [];
      const threats: ThreatReport[] = rawThreats.map((t: any) => ({
        id: t.id || `rep_${Math.random().toString(36).substring(2, 9)}`,
        domain: t.domain || 'unspecified-domain',
        urlPath: t.urlPath || t.url || '/',
        category: (t.category || t.threatType || 'phishing') as any,
        reportedAt: t.reportedAt || t.ingested_at || new Date().toISOString(),
        status: t.status === 'confirmed' || t.status === 'verified'
          ? 'verified'
          : t.status === 'under_investigation'
          ? 'investigating'
          : t.status === 'mitigated'
          ? 'mitigated'
          : 'unconfirmed',
        confidenceScore: t.confidenceScore || 95,
        reporterType: t.provider ? 'partner_feed' : 'automated_sensor',
        corroborationCount: t.corroborationCount || 1,
        targetBrand: t.targetBrand || t.targetedBrand || undefined,
        indicators: t.indicators || t.threatTags || [t.evidenceSummary || 'Adverse indicator detected.'],
        provider: t.provider,
        country: t.country,
        sourceUrl: t.sourceUrl,
      }));

      const rawMetrics = data.metrics || {};
      const metrics: ThreatFeedMetrics = {
        totalThreatsMonitored: rawMetrics.threatsMonitored ?? rawMetrics.totalThreatsMonitored ?? threats.length,
        activeCampaigns24h: rawMetrics.activeCampaigns ?? rawMetrics.activeCampaigns24h ?? 0,
        verifiedMaliciousDomains: rawMetrics.maliciousCount ?? rawMetrics.verifiedMaliciousDomains ?? threats.filter((t) => t.status === 'verified').length,
        communityReportsToday: rawMetrics.analystReportsToday ?? rawMetrics.communityReportsToday ?? 0,
        categoryBreakdown: Array.isArray(rawMetrics.vectorBreakdown) && rawMetrics.vectorBreakdown.length > 0
          ? rawMetrics.vectorBreakdown.map((vb: any) => ({
              category: (vb.category || vb.name.toLowerCase().replace(/\s+/g, '_')) as any,
              name: vb.name || vb.category,
              count: vb.count,
              percentage: vb.percentage ?? ((rawMetrics.threatsMonitored > 0) ? Math.round((vb.count / rawMetrics.threatsMonitored) * 100) : 0),
            }))
          : [],
        providerBreakdown: Array.isArray(rawMetrics.providerBreakdown) ? rawMetrics.providerBreakdown : [],
        geoDistribution: Array.isArray(rawMetrics.geoDistribution) ? rawMetrics.geoDistribution : [],
      };

      return { threats, metrics };
    }
  } catch {
    // API server offline or network timeout — return honest empty state
  }

  return {
    threats: [],
    metrics: EMPTY_TELEMETRY_METRICS,
  };
}

export async function fetchThreatProvidersStatus(): Promise<ThreatProviderStatus[]> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(`${API_BASE_URL}/api/threats/providers`, { signal: controller.signal });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      return Array.isArray(data.providers) ? data.providers : [];
    }
  } catch {
    // Graceful offline fallback
  }
  return [];
}

export async function triggerThreatFeedSync(
  providerId?: string
): Promise<{ success: boolean; sync?: any }> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);
    const res = await fetch(`${API_BASE_URL}/api/threats/sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(providerId ? { providerId } : {}),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      return { success: true, sync: data.sync };
    }
  } catch {
    // Fallback
  }
  return { success: false };
}

export async function submitCommunityThreatReport(
  payload: ThreatSubmissionPayload
): Promise<{ success: boolean; reportId: string }> {
  let hostname = payload.url;
  try {
    const parsed = new URL(payload.url.startsWith('http') ? payload.url : `https://${payload.url}`);
    hostname = parsed.hostname;
  } catch {
    // Keep raw
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500);
    const res = await fetch(`${API_BASE_URL}/api/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: payload.url,
        domain: hostname,
        threatType: payload.category,
        targetedBrand: payload.targetBrand,
        description: payload.notes,
        hasInteracted: payload.hasInteracted,
      }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      return { success: true, reportId: data.reportId };
    }
  } catch {
    // Fallback error
  }

  return { success: false, reportId: '' };
}
