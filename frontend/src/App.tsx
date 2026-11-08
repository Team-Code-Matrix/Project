import { useState, useRef, useEffect } from 'react';
import { AppShell } from './components/layout/AppShell';
import { UrlScanner } from './components/scanner/UrlScanner';
import { ScanProgress } from './components/scanner/ScanProgress';
import { FastPathVerdictCard } from './components/scanner/FastPathVerdictCard';
import { DashboardHeader } from './components/dashboard/DashboardHeader';
import { TrustScoreCircle } from './components/dashboard/TrustScoreCircle';
import { MultiModelGrid } from './components/dashboard/MultiModelGrid';
import { SecurityFindings } from './components/dashboard/SecurityFindings';
import { Recommendations } from './components/dashboard/Recommendations';
import { MethodologyModal } from './components/dashboard/MethodologyModal';
import { CertificateIntelligence } from './components/dashboard/CertificateIntelligence';
import { WebSecurityAudit } from './components/dashboard/WebSecurityAudit';
import { ThreatRelationshipGraph } from './components/dashboard/ThreatRelationshipGraph';
import { ForensicsViewer } from './components/dashboard/ForensicsViewer';
import { ScanHistoryDrawer } from './components/dashboard/ScanHistoryDrawer';
import { BentoFeatureGrid } from './components/visualizations/BentoFeatureGrid';
import { HowItWorksProcess } from './components/visualizations/HowItWorksProcess';
import { DualMotionTicker } from './components/visualizations/DualMotionTicker';
import { ThreatMetrics } from './components/intelligence/ThreatMetrics';
import { ThreatFeedTable } from './components/intelligence/ThreatFeedTable';
import { ReportThreatModal } from './components/intelligence/ReportThreatModal';
import { SecurityModuleView } from './components/modules/SecurityModuleView';
import { InteractiveHeroPanel } from './components/layout/InteractiveHeroPanel';
import { useScan } from './hooks/useScan';
import { INITIAL_THREAT_FEED, THREAT_FEED_METRICS } from './data/threatIntelData';
import { fetchLiveThreatsAndMetrics } from './services/threatIntelService';
import type { ThreatReport, ThreatFeedMetrics } from './types/threatIntel';
import {
  Shield,
  AlertTriangle,
  Activity,
  Lock,
  FileCheck2,
  Network,
  FileSearch,
  Layers,
} from 'lucide-react';

export function App() {
  const {
    isScanning,
    isComplete,
    isError,
    currentStage,
    targetUrl,
    hostname,
    result,
    extendedReport,
    fastPath,
    error,
    history,
    startScan,
    loadHistoryItem,
    clearHistory,
    resetScan,
  } = useScan();

  // Active module view navigation (default is 'overview' which displays the homepage)
  const [activeModule, setActiveModule] = useState<string>('overview');

  const [activeDashboardTab, setActiveDashboardTab] = useState<
    'overview' | 'pki' | 'websec' | 'graph' | 'forensics'
  >('overview');

  const [isMethodologyOpen, setIsMethodologyOpen] = useState(false);
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [reportInitialUrl, setReportInitialUrl] = useState('');

  // Live Threat Intelligence Feed state
  const [threats, setThreats] = useState<ThreatReport[]>(INITIAL_THREAT_FEED);
  const [threatMetrics, setThreatMetrics] = useState<ThreatFeedMetrics>(THREAT_FEED_METRICS);

  useEffect(() => {
    fetchLiveThreatsAndMetrics().then(({ threats: tList, metrics: mData }) => {
      if (tList && tList.length > 0) setThreats(tList);
      if (mData) setThreatMetrics(mData);
    });
  }, []);

  const scannerRef = useRef<HTMLDivElement>(null);
  const resultsRef = useRef<HTMLDivElement>(null);

  const handleScrollToScanner = () => {
    scannerRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  // URL synchronization on mount and parameter change
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const modParam = params.get('module');
    if (modParam) {
      setActiveModule(modParam);
    }
    const urlParam = params.get('url') || params.get('scan');
    if (urlParam) {
      startScan(urlParam);
    }
  }, [startScan]);

  // Support browser back and forward navigation
  useEffect(() => {
    const handlePopState = () => {
      const params = new URLSearchParams(window.location.search);
      const modParam = params.get('module') || 'overview';
      setActiveModule(modParam);
    };

    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  // Module selection with browser history update
  const handleSelectModule = (moduleId: string) => {
    setActiveModule(moduleId);
    const url = new URL(window.location.href);
    if (moduleId === 'overview') {
      url.searchParams.delete('module');
    } else {
      url.searchParams.set('module', moduleId);
    }
    window.history.pushState({ module: moduleId }, '', url.toString());

    if (moduleId === 'overview') {
      handleScrollToScanner();
    } else {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  useEffect(() => {
    if (isComplete && resultsRef.current && activeModule === 'overview') {
      resultsRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, [isComplete, activeModule]);

  const handleOpenReportWithUrl = (urlToReport?: string) => {
    setReportInitialUrl(urlToReport || targetUrl || '');
    setIsReportModalOpen(true);
  };

  return (
    <AppShell
      onScanClick={() => {
        if (activeModule !== 'overview') {
          handleSelectModule('overview');
        }
        handleScrollToScanner();
      }}
      onOpenMethodology={() => handleSelectModule('methodology')}
      onOpenReportModal={() => handleOpenReportWithUrl()}
      onOpenHistory={() => handleSelectModule('history')}
      activeModule={activeModule}
      onSelectModule={handleSelectModule}
      activeHostname={hostname}
      activeTrustScore={result?.score ?? undefined}
    >
      {/* 
        CONDITIONAL RENDERING:
        If activeModule === 'overview', render the complete homepage experience exactly as it was.
        If activeModule !== 'overview', render the dedicated security analysis module view with shared scan context.
      */}
      {activeModule === 'overview' ? (
        <>
          {/* HERO SECTION / PRIMARY SCANNER */}
          <section
            id="scanner"
            ref={scannerRef}
            className="relative pt-8 md:pt-14 pb-16 px-4 max-w-7xl mx-auto w-full flex flex-col items-center"
          >
            {/* Interactive 3D Perspective Hero Terminal Panel */}
            <InteractiveHeroPanel />

            <UrlScanner
              onScan={(url) => startScan(url)}
              isScanning={isScanning}
              initialUrl={targetUrl}
            />

            {/* Fast-Path Synchronous Lane Pre-Detonation Verdict Banner */}
            {fastPath && (
              <div className="w-full max-w-[860px] mx-auto mt-5">
                <FastPathVerdictCard fastPath={fastPath} hostname={hostname} />
              </div>
            )}

            {/* Active Scanning Animation State */}
            {isScanning && (
              <div className="w-full mt-6">
                <ScanProgress
                  currentStage={currentStage}
                  targetUrl={targetUrl}
                  hostname={hostname}
                />
              </div>
            )}

            {/* Error Feedback State */}
            {isError && error && (
              <div className="mt-8 p-5 rounded-2xl bg-shield-danger/15 border border-shield-danger/30 text-rose-300 max-w-2xl mx-auto text-sm text-left flex items-start gap-3 shadow-clay-card animate-fadeIn">
                <AlertTriangle className="w-5 h-5 text-shield-danger shrink-0 mt-0.5" />
                <div>
                  <div className="font-bold uppercase tracking-wider mb-1">Assessment Interrupted</div>
                  <p className="text-shield-text-secondary">{error}</p>
                  <button
                    type="button"
                    onClick={resetScan}
                    className="mt-3 text-xs font-mono text-shield-accent-light hover:underline cursor-pointer"
                  >
                    Clear and retry
                  </button>
                </div>
              </div>
            )}
          </section>

          {/* DEDICATED RESULTS DASHBOARD */}
          {isComplete && result && (
            <section
              id="results"
              ref={resultsRef}
              className="py-12 px-4 max-w-7xl mx-auto w-full space-y-8 animate-fadeIn"
            >
              {/* Dashboard Header Bar with Print, JSON Export, Share */}
              <DashboardHeader
                scanResult={result}
                onReset={resetScan}
                onOpenMethodology={() => handleSelectModule('methodology')}
              />

              {/* Bento-style Score Centerpiece & Summary */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                {/* Centerpiece Trust Score Gauge (Span 5) */}
                <div className="lg:col-span-5 clay-card rounded-3xl border border-shield-border flex items-center justify-center">
                  <TrustScoreCircle
                    score={result.score}
                    riskLevel={result.riskLevel}
                    criticalOverride={result.criticalOverride}
                    overrideReason={result.overrideReason}
                  />
                </div>

                {/* Assessment Plain-Language Summary & Fast Telemetry (Span 7) */}
                <div className="lg:col-span-7 clay-card rounded-3xl p-6 md:p-8 flex flex-col justify-between border border-shield-border">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono uppercase tracking-wider text-[#F3D081]">
                        Executive Analysis Summary
                      </span>
                      <span className="text-xs font-mono text-shield-text-muted">
                        Engine v2.4 (Dual-Lane Deep Detonation)
                      </span>
                    </div>

                    <h3 className="text-xl md:text-2xl font-bold text-shield-text-primary text-left">
                      {result.summary}
                    </h3>

                    <p className="text-xs md:text-sm text-shield-text-secondary leading-relaxed text-left">
                      Evaluated across domain age, DNS reputation, SSL/TLS handshake transparency, deep redirect traversal, and collaborative threat feeds. The score synthesizes individual model verdicts while prioritizing confirmed critical indicators.
                    </p>
                  </div>

                  {/* Fast telemetry tags */}
                  <div className="mt-6 pt-5 border-t border-shield-border/50 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono text-left">
                    <div className="p-3 rounded-xl bg-[#101713]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)]">
                      <div className="text-shield-text-muted text-[11px]">Primary Scheme</div>
                      <div className="font-bold text-shield-text-primary uppercase mt-0.5">
                        {(result as any).primaryScheme || result.protocol.replace(':', '')}
                      </div>
                    </div>

                    <div className="p-3 rounded-xl bg-[#101713]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)]">
                      <div className="text-shield-text-muted text-[11px]">Hosting Origin</div>
                      <div className="font-bold text-shield-text-primary mt-0.5 truncate">
                        {result.country || 'Global Anycast'}
                      </div>
                    </div>

                    <div className="p-3 rounded-xl bg-[#101713]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)]">
                      <div className="text-shield-text-muted text-[11px]">Model Consensus</div>
                      <div className="font-bold text-[#F3D081] mt-0.5">
                        {(result as any).modelConsensus || (
                          result.riskLevel === 'low'
                            ? 'Consensus Clear'
                            : result.criticalOverride
                            ? 'Override Active'
                            : 'Anomalies Noted'
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Multi-Pillar Deep-Dive Module Navigation Tabs */}
              <div className="flex flex-wrap items-center gap-2 p-1.5 rounded-2xl bg-[#101713]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.25)] text-xs font-mono">
                <button
                  type="button"
                  onClick={() => setActiveDashboardTab('overview')}
                  className={`px-4 py-2.5 rounded-xl transition-all cursor-pointer flex items-center gap-2 ${
                    activeDashboardTab === 'overview'
                      ? 'bg-gradient-to-r from-[#FCE7B2] via-[#F3D081] to-[#D4A747] text-[#080B09] font-bold shadow-[0_4px_16px_rgba(243,208,129,0.3)]'
                      : 'text-shield-text-secondary hover:text-shield-text-primary hover:bg-white/[0.05]'
                  }`}
                >
                  <Layers className="w-4 h-4" />
                  <span>Multi-Model Pillars ({result.models.length})</span>
                </button>

                {extendedReport && (
                  <>
                    <button
                      type="button"
                      onClick={() => handleSelectModule('cert-intel')}
                      className="px-4 py-2.5 rounded-xl transition-all cursor-pointer flex items-center gap-2 text-shield-text-secondary hover:text-shield-text-primary hover:bg-white/[0.05]"
                    >
                      <Lock className="w-4 h-4" />
                      <span>PKI & Certificates</span>
                      {extendedReport.backendVerdict === 'PKI_TRUST_COMPROMISED' && (
                        <span className="w-2 h-2 rounded-full bg-purple-400 animate-ping" />
                      )}
                    </button>

                    <button
                      type="button"
                      onClick={() => handleSelectModule('headers')}
                      className="px-4 py-2.5 rounded-xl transition-all cursor-pointer flex items-center gap-2 text-shield-text-secondary hover:text-shield-text-primary hover:bg-white/[0.05]"
                    >
                      <FileCheck2 className="w-4 h-4" />
                      <span>Web Security & Headers</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => handleSelectModule('threat-graph')}
                      className="px-4 py-2.5 rounded-xl transition-all cursor-pointer flex items-center gap-2 text-shield-text-secondary hover:text-shield-text-primary hover:bg-white/[0.05]"
                    >
                      <Network className="w-4 h-4" />
                      <span>Threat Graph</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => handleSelectModule('forensics')}
                      className="px-4 py-2.5 rounded-xl transition-all cursor-pointer flex items-center gap-2 text-shield-text-secondary hover:text-shield-text-primary hover:bg-white/[0.05]"
                    >
                      <FileSearch className="w-4 h-4" />
                      <span>Forensic Vault</span>
                    </button>
                  </>
                )}
              </div>

              {/* TAB CONTENT RENDERING */}
              {activeDashboardTab === 'overview' && (
                <div className="space-y-8 animate-fadeIn">
                  {/* 6 Multi-Model Analysis Cards Grid */}
                  <MultiModelGrid models={result.models} />

                  {/* Security Findings List */}
                  <SecurityFindings findings={result.findings} />

                  {/* Protective Recommendations */}
                  <Recommendations
                    actions={result.recommendedActions}
                    riskLevel={result.riskLevel}
                    onOpenReportModal={() => handleOpenReportWithUrl(result.submittedUrl)}
                  />
                </div>
              )}
            </section>
          )}

          {/* BENTO FEATURE GRID */}
          <BentoFeatureGrid />

          {/* HOW IT WORKS PROCESS FLOW */}
          <HowItWorksProcess />

          {/* DUAL INFINITE MOTION STRIPS */}
          <DualMotionTicker />

          {/* THREAT INTELLIGENCE LIVE SECTION */}
          <section id="threat-intel" className="py-20 px-4 max-w-7xl mx-auto w-full space-y-10 text-left">
            <div className="flex flex-col items-start border-b border-[rgba(120,135,124,0.25)] pb-8">
              <div className="inline-flex items-center gap-2 text-xs font-mono text-[#F3D081] mb-3 uppercase tracking-widest">
                <Activity className="w-3.5 h-3.5 text-[#F3D081]" />
                <span>LIVE THREAT TELEMETRY</span>
              </div>
              <h2 className="swiss-display text-3xl sm:text-4xl md:text-5xl font-black text-[#E9E6DC] mb-4">
                COLLABORATIVE THREAT TELEMETRY.
              </h2>
              <p className="text-[#B7C4B8] text-base md:text-lg leading-relaxed max-w-3xl">
                Real-time telemetry aggregated from community incident reports, automated honeypots, and partner intelligence feeds. Help protect the wider internet ecosystem by reporting active threats.
              </p>
            </div>

            <ThreatMetrics metrics={threatMetrics} />

            <ThreatFeedTable
              threats={threats}
              onScanDomain={(dom) => {
                startScan(dom);
                handleScrollToScanner();
              }}
              onOpenReportModal={() => handleOpenReportWithUrl()}
            />
          </section>
        </>
      ) : (
        /* DEDICATED SECURITY MODULE VIEW */
        <SecurityModuleView
          activeModule={activeModule}
          targetUrl={targetUrl}
          hostname={hostname}
          result={result}
          extendedReport={extendedReport}
          history={history}
          isScanning={isScanning}
          threats={threats}
          threatMetrics={threatMetrics}
          onBackToOverview={() => handleSelectModule('overview')}
          onStartScan={(url) => startScan(url)}
          onSelectScanHistory={(item) => loadHistoryItem(item)}
          onClearHistory={clearHistory}
          onOpenReportModal={handleOpenReportWithUrl}
        />
      )}

      {/* MODALS & DRAWERS */}
      <MethodologyModal
        isOpen={isMethodologyOpen}
        onClose={() => setIsMethodologyOpen(false)}
      />

      <ReportThreatModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        initialUrl={reportInitialUrl}
      />

      <ScanHistoryDrawer
        isOpen={isHistoryOpen}
        onClose={() => setIsHistoryOpen(false)}
        history={history}
        onSelectScan={(item) => loadHistoryItem(item)}
        onClearHistory={clearHistory}
      />
    </AppShell>
  );
}

export default App;
