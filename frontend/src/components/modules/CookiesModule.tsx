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
  result: _result,
  extendedReport,
}) => {
  const cookieData = extendedReport?.webSecurityAudit.cookieSecurity;

  const totalCookies = cookieData?.totalCookiesCount ?? 0;
  const secureMissing = cookieData?.secureFlagsMissingCount ?? 0;
  const httpOnlyMissing = cookieData?.httpOnlyMissingCount ?? 0;
  const sameSiteMissing = cookieData?.sameSiteMissingCount ?? 0;

  const sampleCookies: {
    name: string;
    value: string;
    domain: string;
    path: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite: string;
    expires: string;
    purpose: string;
  }[] = (cookieData as any)?.cookies || [];

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

        {sampleCookies.length === 0 ? (
          <div className="py-12 text-center text-xs font-mono text-shield-text-muted space-y-2">
            <Cookie className="w-8 h-8 text-shield-text-muted/50 mx-auto" />
            <p>No cookie directives observed on evaluated endpoints.</p>
            <p className="text-[11px]">The server did not issue session tokens or tracking identifiers on the initial request.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {sampleCookies.map((ck) => (
              <div
                key={ck.name}
                className="p-4 rounded-2xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/40 space-y-3 transition-all"
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
        )}
      </div>
    </div>
  );
};

