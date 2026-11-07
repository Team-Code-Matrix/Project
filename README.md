# Trust Shield — Intelligent Website Trust Assessment Platform

> **Production-Quality Cybersecurity Intelligence Frontend**  
> Evaluates website URLs through six independent security models to generate an explainable Trust Score (0–100), detailed telemetry, and actionable protective guidance.

---

## 1. Overview

**Trust Shield** is a cybersecurity intelligence application designed to make complex web trust signals accessible to everyday internet users without sacrificing technical rigor.

Users submit a target website URL or domain, and Trust Shield routes the target through six autonomous analysis pillars:
1. **Phishing & Brand Impersonation Detection** — Visual mimicry, brand asset piracy, and credential-harvesting intake endpoints.
2. **URL & Domain Intelligence** — Domain lifespan, registrar history, lexical randomness (Shannon entropy), and punycode homograph attacks.
3. **TLS Certificate & Chain Validation** — Certificate Authority trust path, transparency logs (SCT), SAN host matching, and cipher strength.
4. **Redirect Chain Analysis** — HTTP 3xx hops, cross-domain jurisdictional leaps, and URL shortener resolution.
5. **Web Security Posture** — Defensive HTTP headers (HSTS preload, CSP strictness, X-Frame-Options, Referrer-Policy).
6. **Collaborative Threat Intelligence** — Live community incident reports and curated threat intelligence feeds (PhishTank, URLhaus, AlienVault OTX).

---

## 2. Strict Project Structure

In strict compliance with architectural requirements, **the entire frontend application exists inside the `frontend/` directory**:

```text
TrustShield/
│
├── frontend/                               # All frontend code & configuration
│   ├── public/
│   │   └── favicon.svg                     # Custom Trust Shield geometric lockmark
│   ├── src/
│   │   ├── assets/                         # Static media assets
│   │   ├── components/
│   │   │   ├── layout/
│   │   │   │   ├── AppShell.tsx            # Ambient backdrop & global layout shell
│   │   │   │   ├── Navigation.tsx          # Floating navbar with live status, history & RTL toggle
│   │   │   │   └── Footer.tsx              # Integrity principles, methodology & disclosures
│   │   │   ├── scanner/
│   │   │   │   ├── UrlScanner.tsx          # URL input, paste affordance, normalization, quick chips
│   │   │   │   ├── NormalizationPrompt.tsx # Bare domain to HTTPS normalization suggestion
│   │   │   │   ├── ScanProgress.tsx        # 7-stage animated progress & streaming telemetry logs
│   │   │   │   └── FastPathVerdictCard.tsx # Sub-150ms synchronous pre-detonation verdict card
│   │   │   ├── dashboard/
│   │   │   │   ├── TrustScoreCircle.tsx    # Radial SVG score gauge (0-100) & critical override banner
│   │   │   │   ├── DashboardHeader.tsx     # Target metadata bar, check counters, export/print & share
│   │   │   │   ├── ModelCard.tsx           # Individual model card with expandable evidence & metrics
│   │   │   │   ├── MultiModelGrid.tsx      # Responsive grid of independent model cards
│   │   │   │   ├── SecurityFindings.tsx    # Severity-grouped findings with filter tabs & recommendations
│   │   │   │   ├── Recommendations.tsx     # Actionable protective checklist (Essential/Advisory)
│   │   │   │   ├── MethodologyModal.tsx    # "How score is calculated" comprehensive disclosure
│   │   │   │   ├── CertificateIntelligence.tsx # Deep 5-tab PKI & X.509 audit (Curves, Multi-store, CT, OCSP, CAA)
│   │   │   │   ├── WebSecurityAudit.tsx    # 4-tab appsec audit (Headers, Cookies/CORS, JA4S/Evilginx2, CVEs)
│   │   │   │   ├── ThreatRelationshipGraph.tsx # Interactive @xyflow/react graph (Domains, IPs, ASNs, Certs, Actors)
│   │   │   │   ├── ForensicsViewer.tsx     # Encrypted artifact vault (Safe screenshot, defanged DOM, HAR, PEM)
│   │   │   │   └── ScanHistoryDrawer.tsx   # Slide-out drawer with persistent history recall & management
│   │   │   ├── intelligence/
│   │   │   │   ├── ThreatFeedTable.tsx     # Live threat feed with search & category filtering
│   │   │   │   ├── ThreatMetrics.tsx       # 4 metric cards & Recharts vector distribution chart
│   │   │   │   └── ReportThreatModal.tsx   # Anonymized community threat reporting modal
│   │   │   ├── visualizations/
│   │   │   │   ├── BentoFeatureGrid.tsx    # 6-pillar bento grid with claymorphic surfaces
│   │   │   │   ├── HowItWorksProcess.tsx   # 4-stage visual analysis pipeline
│   │   │   │   └── DualMotionTicker.tsx    # Dual horizontal infinite marquee strips (L-to-R & R-to-L)
│   │   │   └── shared/
│   │   │       ├── RiskBadge.tsx           # Standardized risk level pill
│   │   │       ├── VerdictBadge.tsx        # Model verdict badge (Clear, Suspicious, Malicious, etc.)
│   │   │       ├── SeverityBadge.tsx       # Finding severity badge (Critical, High, Medium, Low, Info)
│   │   │       └── StatusDot.tsx           # Live status indicator dot with ping animation
│   │   ├── context/
│   │   │   └── LanguageContext.tsx         # Bilingual context (English / Arabic) with RTL layout sync
│   │   ├── data/
│   │   │   └── threatIntelData.ts          # Sample threat feed telemetry & distribution metrics
│   │   ├── hooks/
│   │   │   └── useScan.ts                  # Dual-lane scan orchestration hook (Fast-path + Deep-scan + History)
│   │   ├── services/
│   │   │   ├── scanService.ts              # Clean API adapter boundary (IScanService)
│   │   │   ├── scanService.test.ts         # Vitest unit tests for scan service scenarios
│   │   │   ├── websocketService.ts         # Live WebSocket connection manager with reconnect logic
│   │   │   ├── mockScanData.ts             # Initial benchmark test scenarios
│   │   │   └── extendedMockData.ts         # Deep benchmark scenarios (Clean, AiTM Phish, eMudhra PKI Compromise)
│   │   ├── types/
│   │   │   ├── scan.ts                     # UI TypeScript contracts (ScanResult, ModelResult, Finding, etc.)
│   │   │   ├── backend.ts                  # Backend architecture contracts (FastPath, PKI, WebSec, STIX, Forensics)
│   │   │   ├── backendSchemas.ts           # Runtime Zod validation schemas for backend payloads
│   │   │   └── threatIntel.ts              # Threat report and feed metric contracts
│   │   ├── utils/
│   │   │   ├── urlValidator.ts             # Strict RFC URL parsing, normalization & punycode check
│   │   │   ├── urlValidator.test.ts        # Vitest unit tests for URL validation
│   │   │   ├── riskScoreAdapter.ts         # Risk score (0-100) <-> Trust score (100-0) conversion & defanging
│   │   │   ├── riskScoreAdapter.test.ts    # Vitest unit tests for risk score adapter & URL defanger
│   │   │   └── formatters.ts               # Label formatters, date/time, and color token utilities
│   │   ├── App.tsx                         # Main integrated application component with multi-tab dashboard
│   │   ├── main.tsx                        # Root React mounting entry
│   │   └── index.css                       # Design tokens, claymorphic classes, and custom scrollbars
│   ├── package.json
│   ├── tsconfig.json
│   ├── tsconfig.app.json
│   ├── tailwind.config.js
│   ├── postcss.config.js
│   └── vite.config.ts                      # Optimized rollup code-splitting configuration
│
├── intelligent_phishing_trust_platform_architecture.pdf # Full backend architecture specification
├── prd.md                                  # Product Requirements Document
├── skill.md                                # Frontend Implementation Skill Guide
├── agent.md                                # Agent Operational Instructions
└── README.md                               # Project documentation (this file)
```

---

## 3. Technology Stack

- **React 19** (`react`, `react-dom`) — Modern declarative UI library.
- **TypeScript** — Strict typing with explicit boundary data contracts and strict null checks.
- **Vite 8** — Ultra-fast bundler with automated manual code-splitting.
- **Tailwind CSS v3** — Utility-first styling with custom design tokens.
- **@xyflow/react** (`React Flow`) — Interactive, zoomable threat relationship node-edge graph.
- **Zod** — Runtime schema validation for untrusted external backend scan payloads.
- **Recharts** — Responsive SVG data visualizations for threat distribution.
- **Lucide React** — Crisp, semantic icon system.
- **Vitest** — Unit test suite for validation, risk scoring adapter, and service orchestration.

---

## 4. Visual Identity & Design System

The visual design is founded upon **Futuristic Minimalism × Glassmorphism × Soft Claymorphism**:

- **Dominant Brand Accent:** `#367055`
- **Background Foundation:** `#0B100E` (Deep forest graphite)
- **Secondary Background:** `#101713`
- **Base Surface:** `#141D18`
- **Elevated Surface:** `#19251E`
- **Accent Light:** `#79A98B`
- **Text Primary:** `#E8EEE9`
- **Text Secondary:** `#9AA9A0`
- **Border Subtle:** `rgba(190, 215, 198, 0.12)`
- **Border Prominent:** `rgba(190, 215, 198, 0.22)`
- **Status Colors:**
  - Success / Low Risk: `#78B58D`
  - Caution / Warning: `#D7AA62`
  - High Danger: `#EA580C`
  - Critical / Malicious: `#D97878`
  - Informational: `#91A9B7`

### Human-Authored Design Principles
- **No generic AI tropes:** Zero neon purple/blue gradients, no random glowing orbs, no meaningless "AI-powered" labels.
- **Tactile Clay Surfaces:** Subtle inset shadows (`box-shadow: inset 0 2px 5px rgba(0,0,0,0.6)`), tactile button gradients, and gentle 3D elevation on hover.
- **Typography:** `Manrope` for primary interface headings and body, and `IBM Plex Mono` for technical hostnames, hashes, and tabular score figures.
- **Dual Infinite Marquee Strips:** Two counter-rotating decorative text tickers in the About section (Strip A moves left-to-right, Strip B moves right-to-left) with full `prefers-reduced-motion` compliance.

---

## 5. Functional Capabilities

### URL Input & Normalization
- Accepts `http://` and `https://`.
- Detects bare domains (e.g. `github.com`) and offers one-click normalization to `https://github.com/`.
- Rejects dangerous schemes (`javascript:`, `file:`, `data:`, `ftp:`) with accessible inline feedback.
- Deconstructs and displays the target hostname separately so users can inspect spelling and punycode homographs.
- Provides one-click quick benchmark chips for instant demonstration.

### Staged Progress Visualization
- Progresses sequentially through 7 concrete analysis stages:
  1. Parsing URL structure & domain hierarchy
  2. Analysing domain intelligence & WHOIS telemetry
  3. Checking phishing indicators & impersonation patterns
  4. Reviewing TLS certificate signals & chain integrity
  5. Analysing redirect behaviour & destination hops
  6. Assessing web security posture & header hygiene
  7. Correlating signals & computing Trust Score
- Displays real-time streaming monospace telemetry logs.

### Radial Trust Score & Critical Override
- Centered animated radial progress arc rendering the integer score (0–100).
- Categorized risk bands:
  - **80–100:** Lower observed risk (No major warning signals)
  - **60–79:** Caution (Some signals require scrutiny)
  - **30–59:** High risk (Multiple concerning signals detected)
  - **0–29:** Critical risk (Active deceptive or malicious indicators)
  - **Insufficient data** support
- **Critical Override Priority:** If an active credential harvester or malware source is confirmed, a prominent critical override warning is displayed, superseding numerical scores.

### Multi-Model Breakdown & Findings
- **6 Independent Model Cards:** Display model number, category, description, verdict badge (`Clear`, `Suspicious`, `Malicious`, `Unknown`, `Skipped`, `Error`), calibrated confidence percentage, and expandable technical evidence.
- **Severity-Grouped Findings:** Filterable tabs for `Critical`, `High`, `Medium`, `Low`, and `Informational`, detailing source model, technical evidence lines, and concrete remediation advice.
- **Protective Checklist:** Prioritized action items (Essential, Advisory, Monitoring).

### Collaborative Threat Feed & Reporting
- Feed table with search filtering and threat category selection (`Phishing`, `Impersonation`, `Credential Harvesting`, `Crypto Drainer`, `Scam`, `Malware`).
- Interactive Recharts bar breakdown of active threat scheme distribution.
- Complete community threat submission modal with input validation, interaction status, anonymization privacy guarantee, and confirmation reference ID.

---

## 6. Local Setup and Commands

All commands must be executed from inside the `frontend/` directory.

### Prerequisites
- Node.js `v18+` or `v20+` (tested with Node `v24.21.0`)
- npm `v9+` or `v11+`

### 1. Install Dependencies
```bash
cd frontend
npm install
```

### 2. Start Local Development Server
```bash
cd frontend
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser.

### 3. Run Production Build
```bash
cd frontend
npm run build
```
Generates optimized code-split production bundles in `frontend/dist/`.

### 4. Run Unit Test Suite
```bash
cd frontend
npm test
```
Runs 17 Vitest tests across 4 test suites covering RFC URL validation, punycode attacks, bidirectional risk score translation, Zod runtime schema validation, and multi-scenario scan orchestration.

---

## 7. Backend Integration Architecture

The frontend is architected with a decoupled adapter boundary (`frontend/src/services/scanService.ts` and `frontend/src/services/websocketService.ts`):

```ts
export interface IScanService {
  isMock: boolean;
  getFastPathVerdict(rawUrl: string): Promise<FastPathVerdict>;
  initiateScan(
    rawUrl: string,
    onProgress?: (stage: ScanProgressStage, stepIndex: number, totalSteps: number) => void
  ): Promise<ScanResult>;
  getExtendedReport(scanId: string, rawUrl: string): Promise<ExtendedScanReport>;
  getScanHistory(): ScanHistoryItem[];
  saveScanHistory(item: ScanHistoryItem): void;
  clearScanHistory(): void;
}
```

### Dual-Lane Pipeline Architecture:
1. **Synchronous Fast-Path Lane (<150ms):** Calls `getFastPathVerdict(rawUrl)` which queries Redis Bloom filters, Google Safe Browsing v5 hash prefixes, and Mozilla OneCRL CRLite cache. The UI immediately renders a high-visibility `FastPathVerdictCard`.
2. **Asynchronous Deep-Scan Lane (2–15s):** Dispatches job to backend Kafka topics consumed by 4 autonomous worker pools (Pillar 1: DOM Detonation, Pillar 2: PKI Audit, Pillar 3: WebSec & JA4S, Pillar 4: STIX CTI). Telemetry and state changes stream via WebSocket (`ScanWebSocketService`).
3. **Deterministic Verdict Semantics:** Supports the four canonical backend verdicts: `CLEAN`, `SUSPICIOUS`, `MALICIOUS`, and `PKI_TRUST_COMPROMISED`. If a CA or intermediate certificate fails cryptographic validation (e.g., Banbreach / eMudhra October 2026 scenario), the `PKI_TRUST_COMPROMISED` override triggers regardless of the numerical score.
4. **Threat Relationship Graph:** Visualizes STIX 2.1 entities (Domains, IPs, ASNs, SSL Certificates, JA4 hashes, Threat Actors) in an interactive node-edge graph powered by `@xyflow/react`.
5. **MicroVM Forensics Vault:** Displays sanitized static screenshot viewports, defanged DOM trees (`hxxps://` defanging), HTTP HAR network traces, and raw X.509 PEM chains.
6. **Bilingual RTL Support:** Instant English ↔ Arabic translation toggle in the navigation bar dynamically switches text alignment, layout margins, and document direction (`dir="rtl"`, `lang="ar"`).

To switch from the simulated mock adapter to a live backend, set `VITE_USE_MOCK=false` and configure `VITE_API_URL` and `VITE_WS_URL`. No UI components need modification.

