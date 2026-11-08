/**
 * Dynamic API Base URL Resolution for TrustShield.
 *
 * Order of resolution:
 * 1. import.meta.env.VITE_API_URL (configured on Vercel deployment)
 * 2. import.meta.env.VITE_API_BASE_URL (configured on Render / local .env)
 * 3. Fallback to 'http://localhost:8000' ONLY when running locally (hostname === 'localhost' or '127.0.0.1')
 * 4. Otherwise in production, defaults to window.location.origin so requests don't fail-open to localhost.
 * Trims any trailing slashes to guarantee clean routing without double slashes (e.g. //api/scan).
 */

export function getApiBaseUrl(): string {
  const envUrl = (
    (typeof import.meta !== 'undefined' && import.meta.env
      ? (import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL)
      : '') || ''
  ).trim();

  if (envUrl) {
    return envUrl.replace(/\/+$/, '');
  }

  if (typeof window !== 'undefined') {
    const hostname = window.location.hostname;
    if (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '0.0.0.0' ||
      hostname === '::1'
    ) {
      return 'http://localhost:8000';
    }
    // In production without an explicit API env var, default to the current host origin
    return window.location.origin.replace(/\/+$/, '');
  }

  return 'http://localhost:8000';
}

export function getWsBaseUrl(): string {
  const baseUrl = getApiBaseUrl();
  if (baseUrl.startsWith('http')) {
    return baseUrl.replace(/^http(s)?:\/\//, (_, s) => (s ? 'wss://' : 'ws://'));
  }
  if (typeof window !== 'undefined') {
    const isHttps = window.location.protocol === 'https:';
    return `${isHttps ? 'wss:' : 'ws:'}//${window.location.host}`;
  }
  return 'ws://localhost:8000';
}

export const API_BASE_URL = getApiBaseUrl();
export const WS_BASE_URL = getWsBaseUrl();
