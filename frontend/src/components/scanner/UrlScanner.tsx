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
    <div className="w-full max-w-[860px] mx-auto">
      {/* Scanner Container with Translucent Swiss-Brutalist Blueprint Framing */}
      <div className="rounded-2xl p-4 sm:p-5 md:p-6 bg-[#101713]/50 backdrop-blur-[3px] border border-[rgba(120,135,124,0.3)] shadow-[0_20px_50px_rgba(0,0,0,0.55)] relative group">
        
        {/* Terminal Header Strip */}
        <div className="flex items-center justify-between pb-3.5 mb-4 border-b border-[rgba(120,135,124,0.25)] text-xs font-mono">
          <div className="flex items-center gap-2 text-[#B7C4B8]">
            <span className="w-2 h-2 rounded-full bg-[#F3D081] shadow-[0_0_8px_#F3D081] animate-pulse" />
            <span className="font-bold tracking-wider text-[11px] uppercase">TERMINAL // TARGET_INGESTION_SUITE</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="hidden sm:inline-block px-2 py-0.5 rounded bg-[#080B09] border border-[rgba(120,135,124,0.3)] text-[10px] font-mono text-[#B7C4B8] uppercase">
              MICROVM_ISOLATION
            </span>
            <span className="px-2 py-0.5 rounded bg-[#080B09] border border-[rgba(120,135,124,0.3)] text-[10px] font-mono text-[#F3D081] font-semibold uppercase">
              RFC 3986 PARSER
            </span>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="flex flex-col sm:flex-row gap-3">
            {/* Input Wrapper */}
            <div className="relative flex-1 flex items-center rounded-xl bg-[#080B09] border border-[rgba(120,135,124,0.35)] focus-within:border-[#F3D081]/80 focus-within:ring-1 focus-within:ring-[#F3D081]/30 transition-all px-4 py-3.5 shadow-inner">
              <Globe className="w-5 h-5 text-[#78877C] shrink-0 mr-3" />

              <input
                type="text"
                value={inputUrl}
                onChange={handleInputChange}
                disabled={isScanning}
                placeholder="Enter website URL or domain (e.g. https://example.com)"
                className="w-full bg-transparent text-[#E9E6DC] placeholder:text-[#B7C4B8]/50 text-sm md:text-base outline-none font-mono tracking-tight"
                aria-label="Website URL to scan"
              />

              {/* Paste Affordance & Clear Buttons */}
              <div className="flex items-center gap-1.5 ml-2 shrink-0">
                {inputUrl && !isScanning && (
                  <button
                    type="button"
                    onClick={handleClear}
                    title="Clear input"
                    className="p-1.5 rounded-lg text-[#78877C] hover:text-[#E9E6DC] hover:bg-[#202923] transition-colors cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                )}

                <button
                  type="button"
                  onClick={handlePaste}
                  disabled={isScanning}
                  title="Paste from clipboard"
                  className="px-2.5 py-1.5 rounded-lg text-xs font-mono text-[#B7C4B8] hover:text-[#E9E6DC] bg-[#141D18] border border-[rgba(120,135,124,0.3)] hover:border-[#F3D081]/50 transition-colors flex items-center gap-1.5 cursor-pointer"
                >
                  <ClipboardPaste className="w-3.5 h-3.5 text-[#F3D081]" />
                  <span className="hidden sm:inline">Paste</span>
                </button>
              </div>
            </div>

            {/* Scan Action Button */}
            <button
              type="submit"
              disabled={isScanning || !inputUrl.trim()}
              className="px-7 py-3.5 rounded-xl text-sm md:text-base font-black font-mono tracking-wider uppercase text-[#080B09] bg-gradient-to-r from-[#FCE7B2] via-[#F3D081] to-[#D4A747] hover:brightness-105 active:scale-[0.98] shadow-[0_4px_20px_rgba(243,208,129,0.35)] flex items-center justify-center gap-2.5 disabled:opacity-40 disabled:cursor-not-allowed shrink-0 transition-all cursor-pointer"
            >
              <Search className="w-4 h-4 text-[#080B09] stroke-[2.5]" />
              <span>{isScanning ? 'Assessing...' : 'Scan URL'}</span>
            </button>
          </div>

          {/* Paste Notification Feedback */}
          {pasteNotice && (
            <div className="text-xs font-mono text-[#F3D081] px-2 animate-fadeIn flex items-center gap-1.5">
              <span>✓</span>
              <span>{pasteNotice}</span>
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
            <div className="p-3.5 rounded-xl bg-rose-950/30 border border-rose-500/40 text-xs font-mono text-rose-300 flex items-start gap-2.5">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <strong className="font-semibold uppercase tracking-wider">Validation Error:</strong> {validation.message}
              </div>
            </div>
          )}

          {/* Target Hostname Deconstruction Preview */}
          {validation && validation.valid && (
            <div className="pt-2 flex flex-wrap items-center justify-between text-xs font-mono text-[#B7C4B8] border-t border-[rgba(120,135,124,0.25)] gap-2">
              <div className="flex items-center gap-2">
                <span className="text-[#78877C] uppercase tracking-wider text-[11px]">Target:</span>
                <span className="text-[#F3D081] font-bold bg-[#080B09] px-2 py-0.5 rounded border border-[rgba(120,135,124,0.3)]">
                  {validation.hostname}
                </span>
                {validation.isPunycode && (
                  <span className="text-amber-400 bg-amber-950/40 px-2 py-0.5 rounded border border-amber-600/30 flex items-center gap-1 text-[11px]">
                    <AlertCircle className="w-3 h-3" />
                    PUNYCODE_ALERT
                  </span>
                )}
              </div>
              <div className="text-[#78877C] text-[11px]">
                PROTOCOL: <span className="text-[#E9E6DC] font-bold uppercase">{validation.protocol.replace(':', '')}</span>
              </div>
            </div>
          )}
        </form>

        {/* Demo Quick-Select Scenarios */}
        <div className="mt-5 pt-4 border-t border-[rgba(120,135,124,0.25)]">
          <div className="flex items-center justify-between mb-3 text-xs font-mono text-[#78877C]">
            <span className="flex items-center gap-1.5 uppercase tracking-wider text-[11px]">
              <Sparkles className="w-3.5 h-3.5 text-[#F3D081]" />
              Quick Benchmark Scenarios:
            </span>
            <span className="text-[10px] uppercase tracking-wider text-[#78877C]">Click to evaluate</span>
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
                className="text-left p-2.5 rounded-xl bg-[#080B09] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/50 hover:bg-[#141D18] transition-all flex flex-col justify-between group disabled:opacity-50 cursor-pointer"
              >
                <div className="text-xs font-mono font-medium truncate w-full text-[#E9E6DC] group-hover:text-[#F3D081] transition-colors">
                  {scen.label}
                </div>
                <div className="text-[10px] font-mono mt-1 text-[#B7C4B8] flex items-center justify-between">
                  <span>{scen.badge}</span>
                  <span className="opacity-0 group-hover:opacity-100 text-[#F3D081] transition-opacity">→</span>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Supporting Privacy & Methodology Microcopy */}
      <div className="mt-4 flex flex-col sm:flex-row items-center justify-between text-xs text-[#78877C] px-3 gap-2 font-mono">
        <span className="flex items-center gap-1.5 text-[11px]">
          <Lock className="w-3.5 h-3.5 text-[#F3D081]" />
          INSPECT BEFORE YOU INTERACT.
        </span>
        <span className="text-center sm:text-right text-[10px] text-[#78877C] tracking-wide">
          TARGET DOMAINS EVALUATED VIA AIR-GAPPED MICROVM SANDBOXES. ZERO DIRECT CLIENT EXECUTION.
        </span>
      </div>
    </div>
  );
};
