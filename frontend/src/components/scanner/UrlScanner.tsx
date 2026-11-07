import React, { useState, useEffect } from 'react';
import {
  Search,
  ClipboardPaste,
  X,
  AlertCircle,
  Lock,
  Globe,
  Sparkles,
} from 'lucide-react';
import { validateAndNormalizeUrl } from '../../utils/urlValidator';
import type { UrlValidationResult } from '../../utils/urlValidator';
import { NormalizationPrompt } from './NormalizationPrompt';

interface UrlScannerProps {
  onScan: (url: string) => void;
  isScanning: boolean;
  initialUrl?: string;
}

export const UrlScanner: React.FC<UrlScannerProps> = ({
  onScan,
  isScanning,
  initialUrl = '',
}) => {
  const [inputUrl, setInputUrl] = useState(initialUrl);
  const [validation, setValidation] = useState<UrlValidationResult | null>(null);
  const [showNormalizationNotice, setShowNormalizationNotice] = useState(false);
  const [pasteNotice, setPasteNotice] = useState<string | null>(null);

  useEffect(() => {
    if (initialUrl) {
      setInputUrl(initialUrl);
      const res = validateAndNormalizeUrl(initialUrl);
      setValidation(res);
    }
  }, [initialUrl]);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value;
    setInputUrl(val);

    if (val.trim()) {
      const res = validateAndNormalizeUrl(val);
      setValidation(res);
      if (res.valid && res.isBareDomainInput) {
        setShowNormalizationNotice(true);
      } else {
        setShowNormalizationNotice(false);
      }
    } else {
      setValidation(null);
      setShowNormalizationNotice(false);
    }
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setInputUrl(text);
        const res = validateAndNormalizeUrl(text);
        setValidation(res);
        if (res.valid && res.isBareDomainInput) {
          setShowNormalizationNotice(true);
        }
        setPasteNotice('Pasted from clipboard');
        setTimeout(() => setPasteNotice(null), 2500);
      }
    } catch {
      setPasteNotice('Clipboard permission required or unavailable');
      setTimeout(() => setPasteNotice(null), 3000);
    }
  };

  const handleClear = () => {
    setInputUrl('');
    setValidation(null);
    setShowNormalizationNotice(false);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputUrl.trim() || isScanning) return;

    const res = validateAndNormalizeUrl(inputUrl);
    setValidation(res);

    if (res.valid) {
      onScan(res.normalizedUrl);
    }
  };

  const handleApplyNormalization = () => {
    if (validation && validation.valid) {
      setInputUrl(validation.normalizedUrl);
      setShowNormalizationNotice(false);
      onScan(validation.normalizedUrl);
    }
  };

  const demoScenarios = [
    {
      label: 'github.com',
      badge: '94/100 (Safe)',
      color: 'hover:border-shield-success/50 text-emerald-300',
      url: 'https://github.com',
    },
    {
      label: 'login.micros0ft-support-auth.com',
      badge: '14/100 (Phishing)',
      color: 'hover:border-shield-danger/50 text-rose-300',
      url: 'https://login.micros0ft-support-auth.com/verify',
    },
    {
      label: 'bit.ly/secure-account-verify',
      badge: '38/100 (High Risk)',
      color: 'hover:border-amber-500/50 text-amber-300',
      url: 'https://bit.ly/secure-account-verify-302',
    },
    {
      label: 'expired-tls.untrusted-cdn.org',
      badge: '62/100 (Caution)',
      color: 'hover:border-yellow-500/50 text-yellow-300',
      url: 'https://expired-tls.untrusted-cdn-assets.org',
    },
  ];

  return (
    <div className="w-full max-w-4xl mx-auto">
      {/* Scanner Container with Claymorphic & Glass Treatment */}
      <div className="glass-panel-elevated rounded-3xl p-4 sm:p-6 md:p-8 border border-shield-border shadow-clay-card relative">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="flex flex-col sm:flex-row gap-3">
            {/* Input Wrapper */}
            <div className="relative flex-1 flex items-center rounded-2xl clay-input bg-[#0D1410] border border-shield-border/80 focus-within:border-shield-accent transition-all px-4 py-3.5 shadow-clay-input">
              <Globe className="w-5 h-5 text-shield-text-muted shrink-0 mr-3" />

              <input
                type="text"
                value={inputUrl}
                onChange={handleInputChange}
                disabled={isScanning}
                placeholder="Enter website URL or domain (e.g. https://example.com)"
                className="w-full bg-transparent text-shield-text-primary placeholder:text-shield-text-muted/60 text-sm md:text-base outline-none font-mono tracking-tight"
                aria-label="Website URL to scan"
              />

              {/* Paste Affordance & Clear Buttons */}
              <div className="flex items-center gap-1.5 ml-2 shrink-0">
                {inputUrl && !isScanning && (
                  <button
                    type="button"
                    onClick={handleClear}
                    title="Clear input"
                    className="p-1.5 rounded-lg text-shield-text-muted hover:text-shield-text-primary hover:bg-shield-surface transition-colors cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                )}

                <button
                  type="button"
                  onClick={handlePaste}
                  disabled={isScanning}
                  title="Paste from clipboard"
                  className="px-2.5 py-1.5 rounded-lg text-xs font-mono text-shield-text-secondary hover:text-shield-text-primary bg-shield-surface border border-shield-border hover:border-shield-accent/40 transition-colors flex items-center gap-1.5 cursor-pointer"
                >
                  <ClipboardPaste className="w-3.5 h-3.5 text-shield-accent-light" />
                  <span className="hidden sm:inline">Paste</span>
                </button>
              </div>
            </div>

            {/* Scan Action Button */}
            <button
              type="submit"
              disabled={isScanning || !inputUrl.trim()}
              className="clay-button px-7 py-3.5 rounded-2xl text-sm md:text-base font-bold text-white flex items-center justify-center gap-2.5 disabled:opacity-50 disabled:cursor-not-allowed shrink-0 transition-all cursor-pointer"
            >
              <Search className="w-4 h-4" />
              <span>{isScanning ? 'Assessing...' : 'Scan URL'}</span>
            </button>
          </div>

          {/* Paste Notification Feedback */}
          {pasteNotice && (
            <div className="text-xs font-mono text-shield-accent-light px-2 animate-fadeIn">
              ✓ {pasteNotice}
            </div>
          )}

          {/* Normalization prompt */}
          {showNormalizationNotice && validation && validation.valid && (
            <NormalizationPrompt
              originalInput={inputUrl}
              normalizedUrl={validation.normalizedUrl}
              onConfirm={handleApplyNormalization}
              onDismiss={() => setShowNormalizationNotice(false)}
            />
          )}

          {/* Validation Feedback / Warnings */}
          {validation && !validation.valid && (
            <div className="p-3.5 rounded-xl bg-shield-danger/10 border border-shield-danger/30 text-xs text-rose-300 flex items-start gap-2.5">
              <AlertCircle className="w-4 h-4 text-shield-danger shrink-0 mt-0.5" />
              <div>
                <strong className="font-semibold">Validation Issue:</strong> {validation.message}
              </div>
            </div>
          )}

          {/* Target Hostname Deconstruction Preview */}
          {validation && validation.valid && (
            <div className="pt-2 flex flex-wrap items-center justify-between text-xs font-mono text-shield-text-secondary border-t border-shield-border/40 gap-2">
              <div className="flex items-center gap-2">
                <span className="text-shield-text-muted">Target Hostname:</span>
                <span className="text-shield-accent-light font-semibold bg-shield-surface-elevated px-2 py-0.5 rounded border border-shield-border">
                  {validation.hostname}
                </span>
                {validation.isPunycode && (
                  <span className="text-amber-400 bg-amber-950/40 px-2 py-0.5 rounded border border-amber-600/30 flex items-center gap-1">
                    <AlertCircle className="w-3 h-3" />
                    Punycode Homograph Alert
                  </span>
                )}
              </div>
              <div className="text-shield-text-muted text-[11px]">
                Protocol: <span className="text-shield-text-primary uppercase">{validation.protocol.replace(':', '')}</span>
              </div>
            </div>
          )}
        </form>

        {/* Demo Quick-Select Scenarios */}
        <div className="mt-6 pt-5 border-t border-shield-border/50">
          <div className="flex items-center justify-between mb-3 text-xs font-mono text-shield-text-muted">
            <span className="flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-shield-accent-light" />
              Quick Benchmark Scenarios:
            </span>
            <span className="text-[11px] text-shield-text-muted">Click to evaluate</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
            {demoScenarios.map((scen) => (
              <button
                key={scen.url}
                type="button"
                onClick={() => {
                  setInputUrl(scen.url);
                  const res = validateAndNormalizeUrl(scen.url);
                  setValidation(res);
                  setShowNormalizationNotice(false);
                  onScan(scen.url);
                }}
                disabled={isScanning}
                className={`text-left p-2.5 rounded-xl bg-shield-surface/80 border border-shield-border hover:bg-shield-surface-elevated transition-all flex flex-col justify-between group disabled:opacity-50 cursor-pointer ${scen.color}`}
              >
                <div className="text-xs font-mono font-medium truncate w-full text-shield-text-primary group-hover:text-shield-accent-light">
                  {scen.label}
                </div>
                <div className="text-[11px] font-mono mt-1 opacity-80">{scen.badge}</div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Supporting Privacy & Methodology Microcopy */}
      <div className="mt-4 flex flex-col sm:flex-row items-center justify-between text-xs text-shield-text-muted px-3 gap-2">
        <span className="flex items-center gap-1.5 font-mono">
          <Lock className="w-3.5 h-3.5 text-shield-accent-light" />
          Inspect before you interact.
        </span>
        <span className="text-center sm:text-right text-[11px]">
          Target URLs are evaluated via proxy sandboxes and are never contacted directly by your browser.
        </span>
      </div>
    </div>
  );
};
