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
import { useScan } from './hooks/useScan';
import { INITIAL_THREAT_FEED, THREAT_FEED_METRICS } from './data/threatIntelData';
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

  const [activeDashboardTab, setActiveDashboardTab] = useState<
    'overview' | 'pki' | 'websec' | 'graph' | 'forensics'
  >('overview');

  const [isMethodologyOpen, setIsMethodologyOpen] = useState(false);
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [reportInitialUrl, setReportInitialUrl] = useState('');

  const scannerRef = useRef<HTMLDivElement>(null);
  const resultsRef = useRef<HTMLDivElement>(null);

  const handleScrollToScanner = () => {
    scannerRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  useEffect(() => {
    if (isComplete && resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, [isComplete]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const urlParam = params.get('url') || params.get('scan');
    if (urlParam) {
      startScan(urlParam);
    }
  }, [startScan]);

  const handleOpenReportWithUrl = (urlToReport?: string) => {
    setReportInitialUrl(urlToReport || targetUrl || '');
    setIsReportModalOpen(true);
  };

  return (
    <AppShell
      onScanClick={handleScrollToScanner}
      onOpenMethodology={() => setIsMethodologyOpen(true)}
      onOpenReportModal={() => handleOpenReportWithUrl()}
      onOpenHistory={() => setIsHistoryOpen(true)}
    >
      {/* HERO SECTION / PRIMARY SCANNER */}
      <section
        id="scanner"
        ref={scannerRef}
        className="relative pt-12 md:pt-20 pb-16 px-4 max-w-7xl mx-auto w-full flex flex-col items-center text-center"
      >
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-shield-surface border border-shield-border text-xs font-mono text-shield-accent-light mb-6 shadow-clay-sm animate-fadeIn">
          <Shield className="w-3.5 h-3.5 text-shield-accent-light" />
          <span>CYBERSECURITY & WEB REPUTATION ENGINE</span>
        </div>

        <h1 className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-extrabold tracking-tight text-shield-text-primary max-w-4xl mx-auto leading-[1.12] mb-6">
          Not every link deserves <br className="hidden sm:inline" />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-shield-text-primary via-shield-accent-light to-shield-success">
            your trust.
          </span>
        </h1>

        <p className="max-w-2xl mx-auto text-base sm:text-lg text-shield-text-secondary leading-relaxed mb-10">
          Go beyond the lock icon. Analyse websites through multiple security intelligence models and understand the risks before you interact.
        </p>

        <UrlScanner
          onScan={(url) => startScan(url)}
          isScanning={isScanning}
          initialUrl={targetUrl}
        />

        {/* Fast-Path Synchronous Lane Pre-Detonation Verdict Banner */}
        {fastPath && (
          <div className="w-full max-w-4xl mx-auto mt-5">
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
            onOpenMethodology={() => setIsMethodologyOpen(true)}
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
                  <span className="text-xs font-mono uppercase tracking-wider text-shield-accent-light">
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
                <div className="p-3 rounded-xl bg-shield-surface-elevated border border-shield-border/50">
                  <div className="text-shield-text-muted text-[11px]">Primary Scheme</div>
                  <div className="font-bold text-shield-text-primary uppercase mt-0.5">
                    {result.protocol.replace(':', '')}
                  </div>
                </div>

                <div className="p-3 rounded-xl bg-shield-surface-elevated border border-shield-border/50">
                  <div className="text-shield-text-muted text-[11px]">Hosting Origin</div>
                  <div className="font-bold text-shield-text-primary mt-0.5 truncate">
                    {result.country || 'Global Anycast'}
                  </div>
                </div>

                <div className="p-3 rounded-xl bg-shield-surface-elevated border border-shield-border/50">
                  <div className="text-shield-text-muted text-[11px]">Model Consensus</div>
                  <div className="font-bold text-shield-accent-light mt-0.5">
                    {result.riskLevel === 'low'
                      ? 'Consensus Clear'
                      : result.criticalOverride
                      ? 'Override Active'
                      : 'Anomalies Noted'}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Multi-Pillar Deep-Dive Module Navigation Tabs */}
          <div className="flex flex-wrap items-center gap-2 p-1.5 rounded-2xl bg-shield-surface-elevated border border-shield-border text-xs font-mono">
            <button
              type="button"
              onClick={() => setActiveDashboardTab('overview')}
              className={`px-4 py-2.5 rounded-xl transition-all cursor-pointer flex items-center gap-2 ${
                activeDashboardTab === 'overview'
                  ? 'bg-shield-accent text-white font-bold shadow-clay-sm'
                  : 'text-shield-text-secondary hover:text-shield-text-primary hover:bg-shield-surface'
              }`}
            >
              <Layers className="w-4 h-4" />
              <span>Multi-Model Pillars ({result.models.length})</span>
            </button>

            {extendedReport && (
              <>
                <button
                  type="button"
                  onClick={() => setActiveDashboardTab('pki')}
                  className={`px-4 py-2.5 rounded-xl transition-all cursor-pointer flex items-center gap-2 ${
                    activeDashboardTab === 'pki'
                      ? 'bg-shield-accent text-white font-bold shadow-clay-sm'
                      : 'text-shield-text-secondary hover:text-shield-text-primary hover:bg-shield-surface'
                  }`}
                >
                  <Lock className="w-4 h-4" />
                  <span>PKI & Certificates</span>
                  {extendedReport.backendVerdict === 'PKI_TRUST_COMPROMISED' && (
                    <span className="w-2 h-2 rounded-full bg-purple-400 animate-ping" />
                  )}
                </button>

                <button
                  type="button"
                  onClick={() => setActiveDashboardTab('websec')}
                  className={`px-4 py-2.5 rounded-xl transition-all cursor-pointer flex items-center gap-2 ${
                    activeDashboardTab === 'websec'
                      ? 'bg-shield-accent text-white font-bold shadow-clay-sm'
                      : 'text-shield-text-secondary hover:text-shield-text-primary hover:bg-shield-surface'
                  }`}
                >
                  <FileCheck2 className="w-4 h-4" />
                  <span>Web Security & JA4+</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveDashboardTab('graph')}
                  className={`px-4 py-2.5 rounded-xl transition-all cursor-pointer flex items-center gap-2 ${
                    activeDashboardTab === 'graph'
                      ? 'bg-shield-accent text-white font-bold shadow-clay-sm'
                      : 'text-shield-text-secondary hover:text-shield-text-primary hover:bg-shield-surface'
                  }`}
                >
                  <Network className="w-4 h-4" />
                  <span>Threat Graph</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveDashboardTab('forensics')}
                  className={`px-4 py-2.5 rounded-xl transition-all cursor-pointer flex items-center gap-2 ${
                    activeDashboardTab === 'forensics'
                      ? 'bg-shield-accent text-white font-bold shadow-clay-sm'
                      : 'text-shield-text-secondary hover:text-shield-text-primary hover:bg-shield-surface'
                  }`}
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

          {activeDashboardTab === 'pki' && extendedReport && (
            <CertificateIntelligence
              pki={extendedReport.pkiIntelligence}
              isPkiCompromised={extendedReport.backendVerdict === 'PKI_TRUST_COMPROMISED'}
            />
          )}

          {activeDashboardTab === 'websec' && extendedReport && (
            <WebSecurityAudit webSec={extendedReport.webSecurityAudit} />
          )}

          {activeDashboardTab === 'graph' && extendedReport && (
            <ThreatRelationshipGraph graphData={extendedReport.threatIntelligence.graphData} />
          )}

          {activeDashboardTab === 'forensics' && extendedReport && (
            <ForensicsViewer
              forensics={extendedReport.forensics}
              hostname={extendedReport.hostname}
            />
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
      <section id="threat-intel" className="py-20 px-4 max-w-7xl mx-auto w-full space-y-10">
        <div className="flex flex-col items-center text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-shield-surface border border-shield-border text-xs font-mono text-shield-accent-light mb-4">
            <Activity className="w-3.5 h-3.5" />
            <span>GLOBAL COMMUNITY INTELLIGENCE</span>
          </div>
          <h2 className="text-3xl md:text-4xl font-bold tracking-tight text-shield-text-primary mb-4">
            Collaborative Threat Telemetry
          </h2>
          <p className="text-shield-text-secondary text-sm md:text-base leading-relaxed">
            Real-time telemetry aggregated from community incident reports, automated honeypots, and partner intelligence feeds. Help protect the wider internet ecosystem by reporting active threats.
          </p>
        </div>

        <ThreatMetrics metrics={THREAT_FEED_METRICS} />

        <ThreatFeedTable
          threats={INITIAL_THREAT_FEED}
          onScanDomain={(dom) => {
            startScan(dom);
            handleScrollToScanner();
          }}
          onOpenReportModal={() => handleOpenReportWithUrl()}
        />
      </section>

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
