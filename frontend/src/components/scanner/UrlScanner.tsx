import React, { useState, useEffect } from 'react';
import {
  Search,
  ClipboardPaste,
  X,
  AlertCircle,
  Globe,
  Lock,
} from 'lucide-react';
import { validateAndNormalizeUrl } from '../../utils/urlValidator';
import type { UrlValidationResult } from '../../utils/urlValidator';
import { NormalizationPrompt } from './NormalizationPrompt';

const PRESET_SCENARIOS = [
  {
    label: 'youtube.com',
    url: 'https://youtube.com',
    badge: '98/100 (Safe)',
    badgeClass: 'text-emerald-400 bg-emerald-950/40 border-emerald-500/30',
  },
  {
    label: 'login.micros0ft-support-auth.com',
    url: 'https://login.micros0ft-support-auth.com',
    badge: '0/100 (Phishing)',
    badgeClass: 'text-rose-400 bg-rose-950/40 border-rose-500/30',
  },
  {
    label: 'bit.ly/secure-doc-viewer-share',
    url: 'https://bit.ly/secure-doc-viewer-share',
    badge: '38/100 (High Risk)',
    badgeClass: 'text-amber-400 bg-amber-950/40 border-amber-500/30',
  },
  {
    label: 'expired-tls-test.badssl.com',
    url: 'https://expired-tls-test.badssl.com',
    badge: '20/100 (Expired TLS)',
    badgeClass: 'text-yellow-400 bg-yellow-950/40 border-yellow-500/30',
  },
];

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

  const handleSelectPreset = (presetUrl: string) => {
    setInputUrl(presetUrl);
    const res = validateAndNormalizeUrl(presetUrl);
    setValidation(res);
    setShowNormalizationNotice(false);
    onScan(presetUrl);
  };

  const handleApplyNormalization = () => {
    if (validation && validation.valid) {
      setInputUrl(validation.normalizedUrl);
      setShowNormalizationNotice(false);
      onScan(validation.normalizedUrl);
    }
  };

  return (
    <div className="w-full max-w-[860px] mx-auto">
      {/* Clean Glassmorphic Command Bar */}
      <div className="rounded-2xl p-3 sm:p-4 bg-[#101713]/60 backdrop-blur-[4px] border border-[rgba(120,135,124,0.3)] shadow-[0_20px_50px_rgba(0,0,0,0.55)] relative">
        <form onSubmit={handleSubmit} className="space-y-3">
          <div className="flex flex-col sm:flex-row gap-3">
            {/* Input Wrapper */}
            <div className="relative flex-1 flex items-center rounded-xl bg-[#080B09]/80 backdrop-blur-[2px] border border-[rgba(120,135,124,0.35)] focus-within:border-[#F3D081]/80 focus-within:ring-1 focus-within:ring-[#F3D081]/30 transition-all px-4 py-3 shadow-inner">
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
                  className="px-2.5 py-1.5 rounded-lg text-xs font-mono text-[#B7C4B8] hover:text-[#E9E6DC] bg-[#141D18]/70 backdrop-blur-[2px] border border-[rgba(120,135,124,0.3)] hover:border-[#F3D081]/50 transition-colors flex items-center gap-1.5 cursor-pointer"
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
              className="px-7 py-3 rounded-xl text-sm md:text-base font-black font-mono tracking-wider uppercase text-[#080B09] bg-gradient-to-r from-[#FCE7B2] via-[#F3D081] to-[#D4A747] hover:brightness-105 active:scale-[0.98] shadow-[0_4px_20px_rgba(243,208,129,0.35)] flex items-center justify-center gap-2.5 disabled:opacity-40 disabled:cursor-not-allowed shrink-0 transition-all cursor-pointer"
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

          {/* Preset Quick-Scan Buttons */}
          <div className="pt-3 border-t border-[rgba(120,135,124,0.2)]">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
              {PRESET_SCENARIOS.map((scen) => {
                const isSelected = inputUrl === scen.url;
                return (
                  <button
                    key={scen.url}
                    type="button"
                    onClick={() => handleSelectPreset(scen.url)}
                    disabled={isScanning}
                    className={`text-left p-2.5 rounded-xl transition-all flex flex-col justify-between group disabled:opacity-50 cursor-pointer ${
                      isSelected
                        ? 'bg-[#141D18] border border-[#F3D081]/60 shadow-[0_0_12px_rgba(243,208,129,0.2)]'
                        : 'bg-[#080B09]/80 backdrop-blur-[2px] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/40 hover:bg-[#141D18]'
                    }`}
                  >
                    <div className="text-xs font-mono font-medium truncate w-full text-[#E9E6DC] group-hover:text-[#F3D081] transition-colors">
                      {scen.label}
                    </div>
                    <div className="text-[10px] font-mono mt-1.5 flex items-center justify-between">
                      <span className={`px-1.5 py-0.5 rounded border text-[9px] font-bold ${scen.badgeClass}`}>
                        {scen.badge}
                      </span>
                      <span className="opacity-0 group-hover:opacity-100 text-[#F3D081] transition-opacity">
                        →
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </form>
      </div>

      {/* Yellow-Gradient Glassmorphism Security Notice */}
      <div
        className="mt-3.5 w-full flex flex-col sm:flex-row items-center justify-between gap-2.5 font-mono uppercase text-[11px] tracking-[0.08em] transition-all"
        style={{
          padding: '10px 16px',
          borderRadius: '10px',
          background:
            'linear-gradient(90deg, rgba(234, 179, 8, 0.12) 0%, rgba(250, 204, 21, 0.05) 50%, rgba(234, 179, 8, 0.12) 100%)',
          backdropFilter: 'blur(16px)',
          WebkitBackdropFilter: 'blur(16px)',
          border: '1px solid rgba(250, 204, 21, 0.28)',
          boxShadow:
            '0 8px 32px rgba(0, 0, 0, 0.45), 0 0 20px rgba(234, 179, 8, 0.08), inset 0 1px 0 rgba(253, 224, 71, 0.2)',
        }}
      >
        <div className="flex items-center gap-2 text-[#fde047] font-bold shrink-0">
          <Lock className="w-3.5 h-3.5 text-[#fde047] stroke-[2.2]" />
          <span>INSPECT BEFORE YOU INTERACT.</span>
        </div>
        <div className="text-center sm:text-right text-amber-100/70 text-[10px] sm:text-[11px] tracking-[0.08em]">
          TARGET DOMAINS EVALUATED VIA AIR-GAPPED MICROVM SANDBOXES. ZERO DIRECT CLIENT EXECUTION.
        </div>
      </div>
    </div>
  );
};
