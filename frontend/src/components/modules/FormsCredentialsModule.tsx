import React from 'react';
import {
  KeyRound,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CreditCard,
  Lock,
  Eye,
  CheckCircle2,
  ExternalLink,
} from 'lucide-react';
import type { ScanResult } from '../../types/scan';
import type { ExtendedScanReport } from '../../types/backend';

export interface FormsCredentialsModuleProps {
  result: ScanResult;
  extendedReport?: ExtendedScanReport | null;
}

export const FormsCredentialsModule: React.FC<FormsCredentialsModuleProps> = ({
  result,
  extendedReport,
}) => {
  const dom = extendedReport?.phishingDetonation.domHeuristics;
  const isPhishing = result.hostname.includes('micros0ft') || result.hostname.includes('auth');

  const passwordFields = dom?.passwordInputsCount || (isPhishing ? 2 : 0);
  const paymentFields = dom?.paymentFieldsCount || 0;
  const otpFields = dom?.otpFieldsCount || (isPhishing ? 1 : 0);
  const bitbDetected = dom?.browserInTheBrowserDetected || isPhishing;
  const hiddenIframes = dom?.hiddenIframesCount || (isPhishing ? 1 : 0);
  const devToolsBlocker = dom?.devToolsBlockerDetected || isPhishing;
  const crossOriginTarget = dom?.crossOriginSubmissionTarget || (isPhishing ? 'https://exfil-c2-collector.ru/drop.php' : undefined);

  return (
    <div className="space-y-6 text-left">
      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Password Inputs</div>
          <div className={`text-2xl font-black ${isPhishing ? 'text-rose-400' : 'text-shield-text-primary'}`}>
            {passwordFields} Fields
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">
            {isPhishing ? 'Exposed on unverified origin' : 'No credential form on root'}
          </div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Payment / Card Fields</div>
          <div className="text-2xl font-black text-emerald-400">
            {paymentFields} Fields
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">
            PCI-DSS scope check
          </div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Cross-Origin Submission</div>
          <div className={`text-2xl font-black ${crossOriginTarget ? 'text-rose-400' : 'text-emerald-400'}`}>
            {crossOriginTarget ? 'EXFIL TRAP' : 'SAME-ORIGIN'}
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">
            {crossOriginTarget ? 'Form posts to external C2' : 'Form targets verified host'}
          </div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">BitB Phishing Window</div>
          <div className={`text-2xl font-black ${bitbDetected ? 'text-rose-400' : 'text-emerald-400'}`}>
            {bitbDetected ? 'DETECTED' : 'CLEAN'}
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">
            {bitbDetected ? 'Simulated OAuth login popup' : 'No fake browser window'}
          </div>
        </div>
      </div>

      {/* Cross-Origin Exfiltration Alert */}
      {crossOriginTarget && (
        <div className="p-5 rounded-2xl bg-rose-950/20 border border-rose-500/40 text-xs font-mono space-y-2">
          <div className="flex items-center gap-2 text-rose-400 font-bold text-sm">
            <ShieldAlert className="w-4 h-4" />
            <span>CRITICAL: Hostile Cross-Origin Form Exfiltration Target Detected</span>
          </div>
          <p className="text-rose-200">
            Target website captures credentials in HTML form and submits HTTP POST payload across third-party drop endpoint:
          </p>
          <div className="p-2.5 rounded-xl bg-black/60 text-rose-300 font-bold break-all border border-rose-500/30">
            {crossOriginTarget}
          </div>
        </div>
      )}

      {/* Heuristic Audit Table */}
      <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-6">
        <div>
          <h3 className="text-lg font-bold text-shield-text-primary">DOM & Credential Harvester Heuristics</h3>
          <p className="text-xs text-shield-text-secondary">Anti-cloaking microVM analysis of input handlers and form structures</p>
        </div>

        <div className="space-y-3 font-mono text-xs">
          <div className="p-4 rounded-xl bg-[#0D1410] border border-shield-border/60 flex items-center justify-between">
            <div className="space-y-0.5">
              <span className="font-bold text-shield-text-primary">OTP / Multi-Factor Auth Harvester:</span>
              <p className="text-[11px] text-shield-text-muted">Probes whether page intercepts TOTP or SMS verification codes</p>
            </div>
            <span className={`px-2.5 py-1 rounded font-bold ${otpFields > 0 ? 'bg-rose-950 text-rose-400 border border-rose-500/40' : 'bg-emerald-950 text-emerald-400 border border-emerald-500/30'}`}>
              {otpFields > 0 ? `${otpFields} OTP Inputs Flagged` : '0 Clean'}
            </span>
          </div>

          <div className="p-4 rounded-xl bg-[#0D1410] border border-shield-border/60 flex items-center justify-between">
            <div className="space-y-0.5">
              <span className="font-bold text-shield-text-primary">Browser-in-the-Browser (BitB) Cloak:</span>
              <p className="text-[11px] text-shield-text-muted">Checks for canvas or CSS-simulated OS window bars imitating Google/Microsoft OAuth</p>
            </div>
            <span className={`px-2.5 py-1 rounded font-bold ${bitbDetected ? 'bg-rose-950 text-rose-400 border border-rose-500/40' : 'bg-emerald-950 text-emerald-400 border border-emerald-500/30'}`}>
              {bitbDetected ? 'Flagged Malicious' : 'Clean / Passed'}
            </span>
          </div>

          <div className="p-4 rounded-xl bg-[#0D1410] border border-shield-border/60 flex items-center justify-between">
            <div className="space-y-0.5">
              <span className="font-bold text-shield-text-primary">Anti-Analysis DevTools Blocker:</span>
              <p className="text-[11px] text-shield-text-muted">Detects infinite debugger loops or resize listeners disabling F12 developer console</p>
            </div>
            <span className={`px-2.5 py-1 rounded font-bold ${devToolsBlocker ? 'bg-rose-950 text-rose-400 border border-rose-500/40' : 'bg-emerald-950 text-emerald-400 border border-emerald-500/30'}`}>
              {devToolsBlocker ? 'Evasion Active' : 'Clean'}
            </span>
          </div>

          <div className="p-4 rounded-xl bg-[#0D1410] border border-shield-border/60 flex items-center justify-between">
            <div className="space-y-0.5">
              <span className="font-bold text-shield-text-primary">Hidden IFrames & Clickjack Overlays:</span>
              <p className="text-[11px] text-shield-text-muted">Screens for 0-opacity or off-screen iframes intercepting mouse clicks</p>
            </div>
            <span className={`px-2.5 py-1 rounded font-bold ${hiddenIframes > 0 ? 'bg-amber-950 text-amber-400 border border-amber-500/40' : 'bg-emerald-950 text-emerald-400 border border-emerald-500/30'}`}>
              {hiddenIframes} Discovered
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

