import React from 'react';
import {
  LayoutDashboard,
  ShieldCheck,
  Cpu,
  Lock,
  Globe,
  Server,
  Network,
  FileCheck2,
  Cookie,
  Code2,
  KeyRound,
  GitFork,
  Download,
  Files,
  Tags,
  MapPin,
  Activity,
  FileText,
  History,
  Radio,
  Share2,
  FileSearch,
  BookOpen,
  Settings,
} from 'lucide-react';

import type { ScanResult } from '../../types/scan';
import type { ExtendedScanReport, ScanHistoryItem } from '../../types/backend';
import type { ThreatReport, ThreatFeedMetrics } from '../../types/threatIntel';
import { ModuleShell } from './ModuleShell';

// Module Components
import { SecurityChecksModule } from './SecurityChecksModule';
import { TechDetectionModule } from './TechDetectionModule';
import { WhoisLookupModule } from './WhoisLookupModule';
import { PortAssessmentModule } from './PortAssessmentModule';
import { DnsAnalysisModule } from './DnsAnalysisModule';
import { HttpHeadersModule } from './HttpHeadersModule';
import { CookiesModule } from './CookiesModule';
import { ScriptsLibrariesModule } from './ScriptsLibrariesModule';
import { FormsCredentialsModule } from './FormsCredentialsModule';
import { LinksRedirectsModule } from './LinksRedirectsModule';
import { DownloadsModule } from './DownloadsModule';
import { WebsitePagesModule } from './WebsitePagesModule';
import { MetaTagsModule } from './MetaTagsModule';
import { GeoLocationsModule } from './GeoLocationsModule';
import { HttpStatusCodesModule } from './HttpStatusCodesModule';
import { SecurityReportsModule } from './SecurityReportsModule';
import { ScanHistoryModule } from './ScanHistoryModule';
import { MethodologyViewModule } from './MethodologyViewModule';
import { SettingsModule } from './SettingsModule';

// Existing rich components reused directly
import { CertificateIntelligence } from '../dashboard/CertificateIntelligence';
import { ThreatRelationshipGraph } from '../dashboard/ThreatRelationshipGraph';
import { ForensicsViewer } from '../dashboard/ForensicsViewer';
import { ThreatFeedTable } from '../intelligence/ThreatFeedTable';
import { ThreatMetrics } from '../intelligence/ThreatMetrics';
import { INITIAL_THREAT_FEED, THREAT_FEED_METRICS } from '../../data/threatIntelData';

export interface SecurityModuleViewProps {
  activeModule: string;
  targetUrl: string;
  hostname: string;
  result: ScanResult | null;
  extendedReport: ExtendedScanReport | null;
  history: ScanHistoryItem[];
  isScanning: boolean;
  threats?: ThreatReport[];
  threatMetrics?: ThreatFeedMetrics;
  onBackToOverview: () => void;
  onStartScan: (url: string) => void;
  onSelectScanHistory: (item: ScanHistoryItem) => void;
  onClearHistory: () => void;
  onOpenReportModal?: (url?: string) => void;
}

export const SecurityModuleView: React.FC<SecurityModuleViewProps> = ({
  activeModule,
  targetUrl,
  hostname,
  result,
  extendedReport,
  history,
  isScanning,
  threats,
  threatMetrics,
  onBackToOverview,
  onStartScan,
  onSelectScanHistory,
  onClearHistory,
  onOpenReportModal,
}) => {
  const commonShellProps = {
    targetUrl,
    hostname,
    result,
    extendedReport,
    isScanning,
    onBackToOverview,
    onStartScan,
  };

  switch (activeModule) {
    // ------------------------------------------------------------------------
    // Group A: Dashboard
    // ------------------------------------------------------------------------
    case 'security-checks':
      return (
        <ModuleShell
          category="Dashboard"
          moduleName="Security Checks"
          icon={ShieldCheck}
          description="Consolidated audit of security checks across heuristic brand detection, domain tenure, TLS validation, redirect traversal, and threat intelligence."
          {...commonShellProps}
        >
          {result && <SecurityChecksModule result={result} extendedReport={extendedReport} />}
        </ModuleShell>
      );

    case 'tech-detection':
      return (
        <ModuleShell
          category="Dashboard"
          moduleName="Technology Detection"
          icon={Cpu}
          description="Passive fingerprinting of underlying web servers, application frameworks, CMS components, CDN edge nodes, and cryptographic TLS ciphers."
          {...commonShellProps}
        >
          {result && <TechDetectionModule result={result} extendedReport={extendedReport} />}
        </ModuleShell>
      );

    // ------------------------------------------------------------------------
    // Group B: Network Intelligence
    // ------------------------------------------------------------------------
    case 'cert-intel':
      return (
        <ModuleShell
          category="Network Intelligence"
          moduleName="Certificate Intelligence"
          icon={Lock}
          description="RFC 5280 cryptographic chain validation across 5 major trust stores, Certificate Transparency (CT) Merkle proofs, OCSP/CRL revocation status, key entropy, and DNS CAA authorization."
          {...commonShellProps}
        >
          {extendedReport ? (
            <CertificateIntelligence
              pki={extendedReport.pkiIntelligence}
              isPkiCompromised={extendedReport.backendVerdict === 'PKI_TRUST_COMPROMISED'}
            />
          ) : result ? (
            <div className="clay-card rounded-2xl p-6 text-xs font-mono text-shield-text-secondary">
              Evaluating PKI certificate chain...
            </div>
          ) : null}
        </ModuleShell>
      );

    case 'whois':
      return (
        <ModuleShell
          category="Network Intelligence"
          moduleName="WHOIS Lookup"
          icon={Globe}
          description="Authoritative RDAP/WHOIS registry telemetry: sponsoring registrar, domain registration tenure, expiration timeline, nameservers, and EPP status flags."
          {...commonShellProps}
        >
          {result && <WhoisLookupModule result={result} extendedReport={extendedReport} />}
        </ModuleShell>
      );

    case 'ports':
      return (
        <ModuleShell
          category="Network Intelligence"
          moduleName="Port Assessment"
          icon={Server}
          description="Passive observation of public perimeter services, firewalled endpoints, and network exposure aggregated from backend survey telemetry without active client browser probing."
          {...commonShellProps}
        >
          {result && <PortAssessmentModule result={result} extendedReport={extendedReport} />}
        </ModuleShell>
      );

    case 'dns':
      return (
        <ModuleShell
          category="Network Intelligence"
          moduleName="DNS Analysis"
          icon={Network}
          description="Authoritative DNS zone records: Host addresses (A/AAAA), Mail Exchange (MX), Nameservers (NS), SPF & DMARC anti-spoofing policies (TXT), and DNSSEC cryptographic signature status."
          {...commonShellProps}
        >
          {result && <DnsAnalysisModule result={result} extendedReport={extendedReport} />}
        </ModuleShell>
      );

    // ------------------------------------------------------------------------
    // Group C: Website Analysis
    // ------------------------------------------------------------------------
    case 'headers':
      return (
        <ModuleShell
          category="Website Analysis"
          moduleName="HTTP Headers"
          icon={FileCheck2}
          description="Defensive HTTP response headers audit: Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options clickjacking protection, and X-Content-Type-Options nosniff."
          {...commonShellProps}
        >
          {result && <HttpHeadersModule result={result} extendedReport={extendedReport} />}
        </ModuleShell>
      );

    case 'cookies':
      return (
        <ModuleShell
          category="Website Analysis"
          moduleName="Cookies"
          icon={Cookie}
          description="Audit of application session cookies, Secure flags, HttpOnly JavaScript isolation, SameSite CSRF defense policies, and expiration lifetimes."
          {...commonShellProps}
        >
          {result && <CookiesModule result={result} extendedReport={extendedReport} />}
        </ModuleShell>
      );

    case 'scripts':
      return (
        <ModuleShell
          category="Website Analysis"
          moduleName="Scripts & Libraries"
          icon={Code2}
          description="Discovery and integrity auditing of loaded client-side JavaScript libraries, CDNs, Subresource Integrity (SRI) hashes, and correlation with known NVD/CVE vulnerabilities."
          {...commonShellProps}
        >
          {result && <ScriptsLibrariesModule result={result} extendedReport={extendedReport} />}
        </ModuleShell>
      );

    case 'forms':
      return (
        <ModuleShell
          category="Website Analysis"
          moduleName="Forms & Credential Analysis"
          icon={KeyRound}
          description="Anti-phishing inspection of input forms: password inputs, payment fields, cross-origin exfiltration targets, and Browser-in-the-Browser (BitB) simulated login window detection."
          {...commonShellProps}
        >
          {result && <FormsCredentialsModule result={result} extendedReport={extendedReport} />}
        </ModuleShell>
      );

    case 'redirects':
      return (
        <ModuleShell
          category="Website Analysis"
          moduleName="Links & Redirects"
          icon={GitFork}
          description="Full unshortening traversal across HTTP 301/302, Meta Refresh, and window.location scripts. Maps destination IPs, ASNs, and flags domain mismatches."
          {...commonShellProps}
        >
          {result && <LinksRedirectsModule result={result} extendedReport={extendedReport} />}
        </ModuleShell>
      );

    case 'downloads':
      return (
        <ModuleShell
          category="Website Analysis"
          moduleName="Downloads"
          icon={Download}
          description="Inspection of static downloadable resources, binary formats, MIME classifications, and backend file reputation checks for drive-by download traps."
          {...commonShellProps}
        >
          {result && <DownloadsModule result={result} extendedReport={extendedReport} />}
        </ModuleShell>
      );

    case 'pages':
      return (
        <ModuleShell
          category="Website Analysis"
          moduleName="Website Pages"
          icon={Files}
          description="Discovered HTML documents, crawl depth map, response sizes, and HTTP status codes across the evaluated domain scope."
          {...commonShellProps}
        >
          {result && <WebsitePagesModule result={result} extendedReport={extendedReport} />}
        </ModuleShell>
      );

    case 'meta-tags':
      return (
        <ModuleShell
          category="Website Analysis"
          moduleName="Meta Tags"
          icon={Tags}
          description="Extraction and validation of HTML document title, meta descriptions, canonical URLs, OpenGraph preview cards, Twitter metadata, and robots directives."
          {...commonShellProps}
        >
          {result && <MetaTagsModule result={result} extendedReport={extendedReport} />}
        </ModuleShell>
      );

    // ------------------------------------------------------------------------
    // Group D: Reports & Intelligence
    // ------------------------------------------------------------------------
    case 'geo-locations':
      return (
        <ModuleShell
          category="Reports & Intelligence"
          moduleName="Geo Locations"
          icon={MapPin}
          description="IP geolocation, hosting datacenter localization, physical coordinates, and Autonomous System Number (ASN) BGP routing attribution."
          {...commonShellProps}
        >
          {result && <GeoLocationsModule result={result} extendedReport={extendedReport} />}
        </ModuleShell>
      );

    case 'status-codes':
      return (
        <ModuleShell
          category="Reports & Intelligence"
          moduleName="HTTP Status Codes"
          icon={Activity}
          description="HAR transaction ledger breaking down HTTP response statuses (2xx, 3xx, 4xx, 5xx), response latencies, and payload transfer sizes."
          {...commonShellProps}
        >
          {result && <HttpStatusCodesModule result={result} extendedReport={extendedReport} />}
        </ModuleShell>
      );

    case 'reports':
      return (
        <ModuleShell
          category="Reports & Intelligence"
          moduleName="Security Reports"
          icon={FileText}
          description="Consolidated executive assessment brief synthesizing multi-model verdicts, trust and risk scores, ranked findings, and protective recommendations."
          {...commonShellProps}
        >
          {result && <SecurityReportsModule result={result} extendedReport={extendedReport} />}
        </ModuleShell>
      );

    case 'history':
      return (
        <ModuleShell
          category="Reports & Intelligence"
          moduleName="Scan History"
          icon={History}
          description="Personal registry of historical website evaluations with timestamps, verdicts, and one-click report reloading into active analysis context."
          {...commonShellProps}
        >
          <ScanHistoryModule
            history={history}
            onSelectScan={onSelectScanHistory}
            onClearHistory={onClearHistory}
          />
        </ModuleShell>
      );

    case 'threat-intel':
      return (
        <ModuleShell
          category="Reports & Intelligence"
          moduleName="Threat Intelligence"
          icon={Radio}
          description="Real-time STIX 2.1 threat indicators, community honeypot feeds, malicious domain feeds, and federated reputation telemetry correlated with the target domain."
          {...commonShellProps}
        >
          <div className="space-y-6">
            <ThreatMetrics metrics={threatMetrics || THREAT_FEED_METRICS} />
            <ThreatFeedTable
              threats={threats || INITIAL_THREAT_FEED}
              onScanDomain={(dom) => onStartScan(dom)}
              onOpenReportModal={() => onOpenReportModal && onOpenReportModal()}
            />
          </div>
        </ModuleShell>
      );

    case 'threat-graph':
      return (
        <ModuleShell
          category="Reports & Intelligence"
          moduleName="Threat Relationship Graph"
          icon={Share2}
          description="Interactive node-link graph mapping relationships between the target domain, host IPs, ASNs, SSL certificates, JA4 fingerprints, and federated threat actors."
          {...commonShellProps}
        >
          {extendedReport ? (
            <ThreatRelationshipGraph graphData={extendedReport.threatIntelligence.graphData} />
          ) : (
            <div className="clay-card rounded-2xl p-6 text-xs font-mono text-shield-text-secondary">
              Evaluating infrastructure correlation graph...
            </div>
          )}
        </ModuleShell>
      );

    case 'forensics':
      return (
        <ModuleShell
          category="Reports & Intelligence"
          moduleName="Forensic Investigation"
          icon={FileSearch}
          description="MicroVM detonation evidence vault: full-page captured screenshots, redirect traversal logs, sanitized DOM snapshots, and network HAR telemetry."
          {...commonShellProps}
        >
          {extendedReport ? (
            <ForensicsViewer
              forensics={extendedReport.forensics}
              hostname={extendedReport.hostname}
            />
          ) : (
            <div className="clay-card rounded-2xl p-6 text-xs font-mono text-shield-text-secondary">
              Extracting microVM forensic artifacts...
            </div>
          )}
        </ModuleShell>
      );

    // ------------------------------------------------------------------------
    // Group E: System
    // ------------------------------------------------------------------------
    case 'methodology':
      return (
        <ModuleShell
          category="System"
          moduleName="Methodology"
          icon={BookOpen}
          description="Transparent mathematical explanation of TrustShield's 6-model weighted consensus algorithm and critical override veto rules."
          {...commonShellProps}
        >
          <MethodologyViewModule />
        </ModuleShell>
      );

    case 'settings':
      return (
        <ModuleShell
          category="System"
          moduleName="Settings"
          icon={Settings}
          description="Personalize platform canvas aesthetics, language locales (English / Arabic RTL), and backend analysis engine execution flags."
          {...commonShellProps}
        >
          <SettingsModule />
        </ModuleShell>
      );

    default:
      return null;
  }
};
