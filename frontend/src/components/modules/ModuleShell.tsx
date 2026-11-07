import React, { useState } from 'react';
import {
  ArrowLeft,
  Shield,
  Search,
  Globe,
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
            className="p-2.5 rounded-xl bg-[#101713]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.3)] text-[#B7C4B8] hover:text-[#F3D081] hover:border-[#F3D081]/50 transition-all cursor-pointer flex items-center gap-1.5 shadow-sm"
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

        {/* Active Scan Target Badge / Status Indicator */}
        {hostname ? (
          <div className="bg-black/40 backdrop-blur-md border border-[#d4af37]/30 px-3.5 py-1.5 rounded-lg shadow-[0_4px_20px_rgba(0,0,0,0.4)] flex items-center gap-3">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#d4af37] animate-pulse" />
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
              className="p-1 rounded-lg text-[#78877C] hover:text-[#d4af37] transition-colors cursor-pointer"
              title="Re-evaluate target URL"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin text-[#d4af37]' : ''}`} />
            </button>
          </div>
        ) : (
          <div className="bg-black/40 backdrop-blur-md border border-[#d4af37]/30 px-3.5 py-1.5 rounded-lg shadow-[0_4px_20px_rgba(0,0,0,0.4)] flex items-center gap-2.5">
            <span className="w-2 h-2 rounded-full bg-[#d4af37] animate-pulse" />
            <span className="text-xs font-mono font-medium text-[#E9E6DC]">No Target Evaluated Yet</span>
          </div>
        )}
      </div>

      {/* Module Description */}
      <div className="p-4 rounded-xl bg-gradient-to-br from-white/[0.03] via-[#101713]/40 to-[#080B09]/45 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] text-xs text-[#B7C4B8] leading-relaxed">
        <p className="max-w-4xl font-sans">{description}</p>
      </div>

      {/* Main Content Area OR Empty State if no scan is loaded */}
      {result ? (
        <div className="space-y-6">{children}</div>
      ) : (
        <div className="rounded-2xl p-8 md:p-12 text-center bg-gradient-to-br from-white/[0.04] via-[#101713]/40 to-[#080B09]/45 backdrop-blur-[3px] border border-[rgba(120,135,124,0.28)] hover:border-[#F3D081]/40 space-y-6 animate-fadeIn shadow-[0_20px_50px_rgba(0,0,0,0.55)]">
          <div className="max-w-md mx-auto space-y-3">
            <div className="w-14 h-14 rounded-xl bg-[#141D18]/70 backdrop-blur-[2px] border border-[rgba(120,135,124,0.3)] text-[#F3D081] flex items-center justify-center mx-auto shadow-sm">
              <Icon className="w-7 h-7 text-[#F3D081]" />
            </div>
            <h3 className="text-lg md:text-xl font-bold font-sans uppercase tracking-tight text-[#E9E6DC]">
              No Active Target Selected for {moduleName}
            </h3>
            <p className="text-xs md:text-sm text-[#B7C4B8]">
              Enter a website URL or domain below to run live inspection and populate {moduleName.toLowerCase()} intelligence.
            </p>
          </div>

          {/* Inline Quick URL Input */}
          <form onSubmit={handleQuickSubmit} className="max-w-xl mx-auto flex gap-2">
            <div className="relative flex-1 flex items-center rounded-xl bg-[#080B09]/70 backdrop-blur-[3px] border border-[rgba(120,135,124,0.35)] focus-within:border-[#F3D081]/70 px-3.5 py-2.5 text-xs font-mono">
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
        </div>
      )}
    </div>
  );
};
