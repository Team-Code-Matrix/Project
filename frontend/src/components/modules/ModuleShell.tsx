import React, { useState } from 'react';
import {
  ArrowLeft,
  Shield,
  Search,
  Globe,
  Sparkles,
  ClipboardPaste,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
} from 'lucide-react';
import type { ScanResult } from '../../types/scan';
import type { ExtendedScanReport } from '../../types/backend';
import { RiskBadge } from '../shared/RiskBadge';

export interface ModuleShellProps {
  category: string;
  moduleName: string;
  icon: React.ElementType;
  description: string;
  targetUrl?: string;
  hostname?: string;
  result?: ScanResult | null;
  extendedReport?: ExtendedScanReport | null;
  isScanning?: boolean;
  onBackToOverview: () => void;
  onStartScan: (url: string) => void;
  children: React.ReactNode;
}

export const ModuleShell: React.FC<ModuleShellProps> = ({
  category,
  moduleName,
  icon: Icon,
  description,
  targetUrl,
  hostname,
  result,
  extendedReport,
  isScanning = false,
  onBackToOverview,
  onStartScan,
  children,
}) => {
  const [quickInput, setQuickInput] = useState('');

  const demoScenarios = [
    {
      label: 'github.com',
      badge: '94/100 Safe',
      url: 'https://github.com',
      color: 'hover:border-emerald-500/50 text-emerald-400',
    },
    {
      label: 'login.micros0ft-support-auth.com',
      badge: '14/100 Phishing',
      url: 'https://login.micros0ft-support-auth.com/verify',
      color: 'hover:border-rose-500/50 text-rose-400',
    },
    {
      label: 'bit.ly/secure-account-verify',
      badge: '38/100 High Risk',
      url: 'https://bit.ly/secure-account-verify-302',
      color: 'hover:border-amber-500/50 text-amber-400',
    },
    {
      label: 'expired-tls.untrusted-cdn.org',
      badge: '62/100 Caution',
      url: 'https://expired-tls.untrusted-cdn-assets.org',
      color: 'hover:border-yellow-500/50 text-yellow-400',
    },
  ];

  const handleQuickSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (quickInput.trim() && !isScanning) {
      onStartScan(quickInput.trim());
    }
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setQuickInput(text);
      }
    } catch {
      // Permission unavailable
    }
  };

  return (
    <div className="w-full max-w-7xl mx-auto px-4 py-8 md:py-12 space-y-6 text-left animate-fadeIn">
      {/* Top Header Bar & Breadcrumb */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[rgba(120,135,124,0.25)]">
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onBackToOverview}
            className="p-2.5 rounded-xl bg-[#101713] border border-[rgba(120,135,124,0.3)] text-[#B7C4B8] hover:text-[#F3D081] hover:border-[#F3D081]/50 transition-all cursor-pointer flex items-center gap-1.5 shadow-sm"
            title="Return to Main Overview"
          >
            <ArrowLeft className="w-4 h-4" />
            <span className="text-xs font-mono font-medium hidden sm:inline">Overview</span>
          </button>

          <div>
            <div className="flex items-center gap-2 text-xs font-mono text-[#78877C]">
              <span className="uppercase tracking-wider">{category}</span>
              <span>/</span>
              <span className="text-[#F3D081] font-semibold uppercase">{moduleName}</span>
            </div>
            <div className="flex items-center gap-2.5 mt-0.5">
              <Icon className="w-5 h-5 text-[#F3D081] shrink-0" />
              <h1 className="text-xl md:text-2xl font-black font-sans uppercase tracking-tight text-[#E9E6DC]">
                {moduleName}
              </h1>
            </div>
          </div>
        </div>

        {/* Active Scan Target Badge */}
        {hostname ? (
          <div className="flex items-center gap-3 p-2 px-3.5 rounded-xl bg-[#101713] border border-[rgba(120,135,124,0.3)] shadow-sm">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#F3D081] animate-pulse" />
              <span className="text-xs font-mono text-[#78877C]">Target:</span>
              <span className="text-xs font-mono font-bold text-[#E9E6DC] truncate max-w-[180px] sm:max-w-[240px]">
                {hostname}
              </span>
            </div>

            {result && (
              <RiskBadge
                level={result.riskLevel}
              />
            )}

            <button
              type="button"
              onClick={() => targetUrl && onStartScan(targetUrl)}
              disabled={isScanning}
              className="p-1.5 rounded-lg text-[#78877C] hover:text-[#F3D081] transition-colors cursor-pointer"
              title="Re-evaluate target URL"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin text-[#F3D081]' : ''}`} />
            </button>
          </div>
        ) : (
          <div className="text-xs font-mono text-[#78877C] flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#F3D081]" />
            <span>No Target Evaluated Yet</span>
          </div>
        )}
      </div>

      {/* Module Description & Telemetry Metadata Banner */}
      <div className="p-4 rounded-xl bg-[#101713]/85 border border-[rgba(120,135,124,0.25)] text-xs text-[#B7C4B8] leading-relaxed flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <p className="max-w-3xl font-sans">{description}</p>
        <div className="flex items-center gap-2 shrink-0">
          <span className="px-2 py-0.5 rounded bg-[#080B09] text-[10px] font-mono text-[#F3D081] border border-[rgba(120,135,124,0.3)] uppercase font-semibold">
            Passive Telemetry
          </span>
          <span className="px-2 py-0.5 rounded bg-[#080B09] text-[10px] font-mono text-[#78877C] border border-[rgba(120,135,124,0.3)] uppercase">
            Engine v2.4
          </span>
        </div>
      </div>

      {/* Main Content Area OR Empty State if no scan is loaded */}
      {result ? (
        <div className="space-y-6">{children}</div>
      ) : (
        <div className="rounded-2xl p-8 md:p-12 text-center bg-[#101713]/90 border border-[rgba(120,135,124,0.3)] space-y-8 animate-fadeIn shadow-[0_20px_50px_rgba(0,0,0,0.6)]">
          <div className="max-w-md mx-auto space-y-3">
            <div className="w-14 h-14 rounded-xl bg-[#141D18] border border-[rgba(120,135,124,0.3)] text-[#F3D081] flex items-center justify-center mx-auto shadow-sm">
              <Icon className="w-7 h-7 text-[#F3D081]" />
            </div>
            <h3 className="text-lg md:text-xl font-bold font-sans uppercase tracking-tight text-[#E9E6DC]">
              No Active Target Selected for {moduleName}
            </h3>
            <p className="text-xs md:text-sm text-[#B7C4B8]">
              Enter any website URL or domain below, or pick a benchmark security scenario to populate real-time {moduleName.toLowerCase()} intelligence.
            </p>
          </div>

          {/* Inline Quick URL Input */}
          <form onSubmit={handleQuickSubmit} className="max-w-xl mx-auto flex gap-2">
            <div className="relative flex-1 flex items-center rounded-xl bg-[#080B09] border border-[rgba(120,135,124,0.35)] focus-within:border-[#F3D081]/70 px-3.5 py-2.5 text-xs font-mono">
              <Globe className="w-4 h-4 text-[#78877C] mr-2.5 shrink-0" />
              <input
                type="text"
                value={quickInput}
                onChange={(e) => setQuickInput(e.target.value)}
                placeholder="Enter website (e.g. https://example.com)"
                className="w-full bg-transparent text-[#E9E6DC] placeholder:text-[#B7C4B8]/50 outline-none"
              />
              <button
                type="button"
                onClick={handlePaste}
                className="p-1 rounded text-[#78877C] hover:text-[#F3D081] transition-colors ml-1"
                title="Paste from clipboard"
              >
                <ClipboardPaste className="w-3.5 h-3.5" />
              </button>
            </div>
            <button
              type="submit"
              disabled={isScanning || !quickInput.trim()}
              className="px-5 py-2.5 rounded-xl text-xs font-mono font-bold tracking-wider uppercase text-[#080B09] bg-gradient-to-r from-[#FCE7B2] via-[#F3D081] to-[#D4A747] hover:brightness-105 active:scale-[0.98] shadow-sm flex items-center gap-1.5 disabled:opacity-40 cursor-pointer shrink-0 transition-all"
            >
              <Search className="w-3.5 h-3.5 stroke-[2.5]" />
              <span>{isScanning ? 'Evaluating...' : 'Assess'}</span>
            </button>
          </form>

          {/* Quick Select Benchmark Scenarios */}
          <div className="max-w-3xl mx-auto pt-6 border-t border-[rgba(120,135,124,0.25)] space-y-3">
            <div className="text-xs font-mono text-[#78877C] flex items-center justify-center gap-1.5 uppercase tracking-wider">
              <Sparkles className="w-3.5 h-3.5 text-[#F3D081]" />
              <span>Or click a benchmark scenario to evaluate:</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
              {demoScenarios.map((scen) => (
                <button
                  key={scen.url}
                  type="button"
                  onClick={() => onStartScan(scen.url)}
                  disabled={isScanning}
                  className="text-left p-3 rounded-xl bg-[#080B09] border border-[rgba(120,135,124,0.25)] hover:border-[#F3D081]/50 hover:bg-[#141D18] transition-all flex flex-col justify-between group cursor-pointer"
                >
                  <span className="text-xs font-mono font-medium truncate w-full text-[#E9E6DC] group-hover:text-[#F3D081] transition-colors">
                    {scen.label}
                  </span>
                  <span className="text-[10px] font-mono mt-1 text-[#B7C4B8]">{scen.badge}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
