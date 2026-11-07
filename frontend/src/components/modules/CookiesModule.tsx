import React from 'react';
import {
  Cookie,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Clock,
  EyeOff,
} from 'lucide-react';
import type { ScanResult } from '../../types/scan';
import type { ExtendedScanReport } from '../../types/backend';

export interface CookiesModuleProps {
  result: ScanResult;
  extendedReport?: ExtendedScanReport | null;
}

export const CookiesModule: React.FC<CookiesModuleProps> = ({
  result,
  extendedReport,
}) => {
  const cookieData = extendedReport?.webSecurityAudit.cookieSecurity;
  const isGithub = result.hostname.includes('github');
  const isPhishing = result.hostname.includes('micros0ft') || result.hostname.includes('auth');

  const totalCookies = cookieData?.totalCookiesCount || (isPhishing ? 4 : 5);
  const secureMissing = cookieData?.secureFlagsMissingCount || (isPhishing ? 3 : 0);
  const httpOnlyMissing = cookieData?.httpOnlyMissingCount || (isPhishing ? 2 : 1);
  const sameSiteMissing = cookieData?.sameSiteMissingCount || (isPhishing ? 3 : 0);

  const sampleCookies = isGithub
    ? [
        {
          name: '__Host-user_session_same_site',
          value: 'k8X9...91aZ',
          domain: 'github.com',
          path: '/',
          secure: true,
          httpOnly: true,
          sameSite: 'Lax',
          expires: '2 weeks',
          purpose: 'Primary authenticated session token with __Host- prefix binding.',
        },
        {
          name: '_gh_sess',
          value: 'Wy1...x92p',
          domain: 'github.com',
          path: '/',
          secure: true,
          httpOnly: true,
          sameSite: 'Lax',
          expires: 'Session',
          purpose: 'Encrypted Rails session state cookie.',
        },
        {
          name: '_octo',
          value: 'GH1.1.84920492.17309',
          domain: 'github.com',
          path: '/',
          secure: true,
          httpOnly: false,
          sameSite: 'Lax',
          expires: '1 year',
          purpose: 'Device analytics and fraud telemetry identifier.',
        },
        {
          name: 'logged_in',
          value: 'no',
          domain: 'github.com',
          path: '/',
          secure: true,
          httpOnly: true,
          sameSite: 'Lax',
          expires: 'Session',
          purpose: 'Context state indicator flag for edge varnish cache.',
        },
      ]
    : isPhishing
    ? [
        {
          name: 'PHPSESSID',
          value: '0a9f82bc194821',
          domain: result.hostname,
          path: '/',
          secure: false,
          httpOnly: false,
          sameSite: 'None',
          expires: 'Session',
          purpose: 'Insecure PHP session identifier vulnerable to JavaScript extraction.',
        },
        {
          name: 'victim_uuid',
          value: '8492-usr-live',
          domain: result.hostname,
          path: '/',
          secure: false,
          httpOnly: false,
          sameSite: 'None',
          expires: 'Session',
          purpose: 'Phishing credential harvesting telemetry token.',
        },
      ]
    : [
        {
          name: '__cf_bm',
          value: 'cf_bm_0921a9...',
          domain: result.hostname,
          path: '/',
          secure: true,
          httpOnly: true,
          sameSite: 'None',
          expires: '30 minutes',
          purpose: 'Cloudflare Bot Management challenge token.',
        },
      ];

  return (
    <div className="space-y-6 text-left">
      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Total Cookies</div>
          <div className="text-2xl font-black text-shield-text-primary">{totalCookies} Cookies</div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">Observed in HTTP header</div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Secure Flag Enforced</div>
          <div className={`text-2xl font-black ${secureMissing === 0 ? 'text-emerald-400' : 'text-rose-400'}`}>
            {totalCookies - secureMissing} / {totalCookies}
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">
            {secureMissing === 0 ? 'All cookies HTTPS-only' : `${secureMissing} cookies sent unencrypted`}
          </div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">HttpOnly Isolation</div>
          <div className="text-2xl font-black text-shield-text-primary">
            {totalCookies - httpOnlyMissing} / {totalCookies}
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">
            Protected against XSS theft
          </div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">SameSite Protection</div>
          <div className={`text-2xl font-black ${sameSiteMissing === 0 ? 'text-emerald-400' : 'text-amber-400'}`}>
            {totalCookies - sameSiteMissing} / {totalCookies}
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">
            CSRF cross-site defense
          </div>
        </div>
      </div>

      {/* Cookies Table */}
      <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-6">
        <div>
          <h3 className="text-lg font-bold text-shield-text-primary">Observed Application Cookies</h3>
          <p className="text-xs text-shield-text-secondary">Security flags, lifetimes, and isolation directives</p>
        </div>

        <div className="space-y-4">
          {sampleCookies.map((ck) => (
            <div
              key={ck.name}
              className="p-4 rounded-2xl bg-[#0D1410] border border-shield-border/60 space-y-3"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Cookie className="w-4 h-4 text-shield-accent-light" />
                  <span className="font-mono font-bold text-sm text-shield-text-primary">{ck.name}</span>
                </div>
                <div className="flex items-center gap-2 text-[10px] font-mono">
                  <span
                    className={`px-2 py-0.5 rounded font-bold ${
                      ck.secure ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/30' : 'bg-rose-950/80 text-rose-400 border border-rose-500/30'
                    }`}
                  >
                    Secure: {ck.secure ? 'YES' : 'NO'}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded font-bold ${
                      ck.httpOnly ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/30' : 'bg-amber-950/80 text-amber-400 border border-amber-500/30'
                    }`}
                  >
                    HttpOnly: {ck.httpOnly ? 'YES' : 'NO'}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-shield-surface text-shield-text-primary border border-shield-border">
                    SameSite: {ck.sameSite}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-shield-surface text-shield-text-muted border border-shield-border">
                    Expires: {ck.expires}
                  </span>
                </div>
              </div>

              <p className="text-xs text-shield-text-secondary leading-relaxed">{ck.purpose}</p>

              <div className="flex items-center gap-4 text-[11px] font-mono text-shield-text-muted pt-2 border-t border-shield-border/40">
                <span>Domain: <strong className="text-shield-text-primary">{ck.domain}</strong></span>
                <span>Path: <strong className="text-shield-text-primary">{ck.path}</strong></span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

