import React, { useState } from 'react';
import {
  Settings,
  Moon,
  Globe2,
  Sliders,
  Shield,
  Zap,
  Check,
  RefreshCw,
} from 'lucide-react';
import { useLanguage } from '../../context/LanguageContext';

export const SettingsModule: React.FC = () => {
  const { language, setLanguage, t, isRtl } = useLanguage();

  const [fastPathEnabled, setFastPathEnabled] = useState(true);
  const [ctLogsValidation, setCtLogsValidation] = useState(true);
  const [passivePorts, setPassivePorts] = useState(true);
  const [asciiGlowLevel, setAsciiGlowLevel] = useState<'subtle' | 'standard' | 'high'>('standard');
  const [savedNotice, setSavedNotice] = useState(false);

  const handleSave = () => {
    setSavedNotice(true);
    setTimeout(() => setSavedNotice(false), 2500);
  };

  return (
    <div className="space-y-6 text-left">
      {/* Top Banner */}
      <div className="p-5 rounded-2xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.28)] hover:border-[#F3D081]/40 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <span className="text-xs font-mono text-[#F3D081] uppercase tracking-wider">
            Configuration & Preferences
          </span>
          <h2 className="text-lg md:text-xl font-bold text-shield-text-primary">
            Platform Engine & Display Settings
          </h2>
        </div>

        <button
          type="button"
          onClick={handleSave}
          className="px-4 py-2 rounded-xl bg-gradient-to-r from-[#FCE7B2] via-[#F3D081] to-[#D4A747] text-[#080B09] font-mono font-bold text-xs flex items-center gap-2 cursor-pointer shadow-clay-sm hover:scale-[1.02] active:scale-[0.98] transition-all self-start sm:self-auto"
        >
          {savedNotice ? <Check className="w-4 h-4 text-[#080B09]" /> : <RefreshCw className="w-4 h-4 text-[#080B09]" />}
          <span>{savedNotice ? 'Saved!' : 'Save Preferences'}</span>
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Appearance & Visualization */}
        <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-5">
          <div className="flex items-center gap-2.5 pb-3 border-b border-shield-border/50">
            <Moon className="w-4 h-4 text-shield-accent-light" />
            <h3 className="text-sm font-bold text-shield-text-primary font-mono uppercase tracking-wider">
              Visual & Theme Identity
            </h3>
          </div>

          <div className="space-y-4 font-mono text-xs">
            <div className="space-y-1">
              <label className="text-shield-text-primary font-bold">Theme Canvas</label>
              <div className="grid grid-cols-2 gap-2 pt-1">
                <button
                  type="button"
                  className="p-3 rounded-xl bg-[#080B09] border border-emerald-500 text-emerald-400 font-bold text-left flex items-center justify-between"
                >
                  <span>Obsidian Dark (#080B09)</span>
                  <span className="w-2 h-2 rounded-full bg-emerald-400" />
                </button>
                <button
                  type="button"
                  className="p-3 rounded-xl bg-[#141D18] border border-shield-border text-shield-text-muted text-left"
                >
                  <span>Forest Charcoal (#202923)</span>
                </button>
              </div>
            </div>

            <div className="space-y-1 pt-2">
              <label className="text-shield-text-primary font-bold">ASCII World Map Cursor Glow</label>
              <div className="grid grid-cols-3 gap-2 pt-1">
                {(['subtle', 'standard', 'high'] as const).map((lvl) => (
                  <button
                    key={lvl}
                    type="button"
                    onClick={() => setAsciiGlowLevel(lvl)}
                    className={`p-2.5 rounded-xl capitalize font-bold transition-colors cursor-pointer text-center ${
                      asciiGlowLevel === lvl
                        ? 'bg-shield-accent text-white border border-emerald-400'
                        : 'bg-shield-surface text-shield-text-secondary border border-shield-border'
                    }`}
                  >
                    {lvl}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Language & Localization */}
        <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-5">
          <div className="flex items-center gap-2.5 pb-3 border-b border-shield-border/50">
            <Globe2 className="w-4 h-4 text-shield-accent-light" />
            <h3 className="text-sm font-bold text-shield-text-primary font-mono uppercase tracking-wider">
              Localization & Language
            </h3>
          </div>

          <div className="space-y-4 font-mono text-xs">
            <div className="space-y-1">
              <label className="text-shield-text-primary font-bold">Active Interface Language</label>
              <div className="grid grid-cols-2 gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => setLanguage('en')}
                  className={`p-3 rounded-xl font-bold transition-all text-left flex items-center justify-between cursor-pointer ${
                    language === 'en'
                      ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500'
                      : 'bg-shield-surface text-shield-text-secondary border border-shield-border'
                  }`}
                >
                  <span>English (LTR)</span>
                  {language === 'en' && <Check className="w-4 h-4 text-emerald-400" />}
                </button>

                <button
                  type="button"
                  onClick={() => setLanguage('ar')}
                  className={`p-3 rounded-xl font-bold transition-all text-left flex items-center justify-between cursor-pointer ${
                    language === 'ar'
                      ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500'
                      : 'bg-shield-surface text-shield-text-secondary border border-shield-border'
                  }`}
                >
                  <span>العربية (RTL)</span>
                  {language === 'ar' && <Check className="w-4 h-4 text-emerald-400" />}
                </button>
              </div>
            </div>

            <p className="text-[11px] text-shield-text-muted leading-relaxed pt-2">
              Supports bidirectional layout (RTL/LTR) for international intelligence teams across English and Arabic locales.
            </p>
          </div>
        </div>

        {/* Engine Telemetry Controls */}
        <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-5 md:col-span-2">
          <div className="flex items-center gap-2.5 pb-3 border-b border-shield-border/50">
            <Zap className="w-4 h-4 text-shield-accent-light" />
            <h3 className="text-sm font-bold text-shield-text-primary font-mono uppercase tracking-wider">
              Analysis Engine Execution Flags
            </h3>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
            <div className="p-4 rounded-2xl bg-[#080B09]/60 backdrop-blur-[3px] border border-shield-border/60 hover:border-[#F3D081]/30 transition-all flex items-center justify-between">
              <div>
                <span className="font-bold text-shield-text-primary">Fast-Path Synchronous Lane:</span>
                <p className="text-[11px] text-shield-text-muted mt-0.5">Sub-150ms Bloom filter pre-evaluation</p>
              </div>
              <button
                type="button"
                onClick={() => setFastPathEnabled(!fastPathEnabled)}
                className={`w-11 h-6 rounded-full transition-colors relative cursor-pointer ${
                  fastPathEnabled ? 'bg-[#F3D081]' : 'bg-zinc-700'
                }`}
              >
                <span
                  className={`w-4 h-4 rounded-full bg-[#080B09] absolute top-1 transition-transform ${
                    fastPathEnabled ? 'left-6' : 'left-1'
                  }`}
                />
              </button>
            </div>

            <div className="p-4 rounded-2xl bg-[#080B09]/60 backdrop-blur-[3px] border border-shield-border/60 hover:border-[#F3D081]/30 transition-all flex items-center justify-between">
              <div>
                <span className="font-bold text-shield-text-primary">Certificate Transparency CT:</span>
                <p className="text-[11px] text-shield-text-muted mt-0.5">Verify Merkle inclusion proofs</p>
              </div>
              <button
                type="button"
                onClick={() => setCtLogsValidation(!ctLogsValidation)}
                className={`w-11 h-6 rounded-full transition-colors relative cursor-pointer ${
                  ctLogsValidation ? 'bg-[#F3D081]' : 'bg-zinc-700'
                }`}
              >
                <span
                  className={`w-4 h-4 rounded-full bg-[#080B09] absolute top-1 transition-transform ${
                    ctLogsValidation ? 'left-6' : 'left-1'
                  }`}
                />
              </button>
            </div>

            <div className="p-4 rounded-2xl bg-[#080B09]/60 backdrop-blur-[3px] border border-shield-border/60 hover:border-[#F3D081]/30 transition-all flex items-center justify-between">
              <div>
                <span className="font-bold text-shield-text-primary">Passive Port Assessment:</span>
                <p className="text-[11px] text-shield-text-muted mt-0.5">Query authorized edge survey telemetry</p>
              </div>
              <button
                type="button"
                onClick={() => setPassivePorts(!passivePorts)}
                className={`w-11 h-6 rounded-full transition-colors relative cursor-pointer ${
                  passivePorts ? 'bg-[#F3D081]' : 'bg-zinc-700'
                }`}
              >
                <span
                  className={`w-4 h-4 rounded-full bg-[#080B09] absolute top-1 transition-transform ${
                    passivePorts ? 'left-6' : 'left-1'
                  }`}
                />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

