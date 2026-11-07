# Product Requirements Document — TrustLens

**Product:** TrustLens  
**Document type:** Frontend PRD  
**Status:** Prototype-ready  
**Scope:** Frontend experience only

## 1. Product overview

TrustLens is a web-security intelligence interface. A person submits a website URL and receives an explainable trust assessment assembled from multiple independent analysis models.

The experience should make complex security signals understandable without implying that a single score can guarantee safety. The interface presents a **Trust Score from 0–100**, a risk label, model-level results, evidence, and practical next steps.

This PRD defines the frontend only. All scan results shown before backend integration must be clearly identified as demo or simulated data.

## 2. Product goals

- Make a multi-signal website assessment approachable for non-specialists.
- Show how the overall score is composed instead of presenting an unexplained number.
- Surface phishing, impersonation, redirect, TLS/certificate, and web-configuration signals in one place.
- Make uncertainty and missing evidence visible.
- Encourage responsible reporting and collaborative threat intelligence.
- Establish a visual system that feels calm, precise, and security-focused.

### Non-goals for the frontend release

- Performing real vulnerability scans in the browser.
- Claiming that a site is safe because it has HTTPS.
- Guaranteeing that a URL is harmless based on a score.
- Running exploit attempts, credential submission, port scans, or intrusive tests.
- Storing or sharing user-submitted URLs without an explicit product policy and consent.

## 3. Target users

1. **Everyday internet users** checking links received through messages, ads, email, or social platforms.
2. **Students and job seekers** checking university, scholarship, recruitment, and application portals.
3. **Small teams and organisations** reviewing links before sharing them internally.
4. **Security-aware users** who want evidence, model breakdowns, and certificate details.

## 4. Core user journey

1. User lands on the homepage.
2. User pastes a complete URL into the primary scan field.
3. Frontend validates URL syntax and displays the normalized hostname.
4. User starts the assessment.
5. A staged progress view shows the analysis categories being evaluated.
6. Results appear with an overall score, risk label, model verdicts, and evidence.
7. User can expand findings, copy a shareable summary, or submit a community report.
8. User can start another scan.

## 5. Information architecture

### Main navigation

- **Overview** — product landing and URL scanner.
- **How it works** — model methodology and score explanation.
- **Threat intelligence** — anonymised community signals and recent reports.
- **About** — mission, principles, and trust limitations.

Keep navigation compact. On smaller screens, collapse it into an accessible menu.

### Homepage layout

1. **Top bar**
   - Wordmark: TrustLens (working name).
   - Navigation links.
   - Small status indicator such as “Threat intelligence online” only when backed by a real service; otherwise label it “Demo environment”.

2. **Hero / scanner**
   - Eyebrow: “A clearer view of web trust”.
   - Headline: “Know what’s behind the link.”
   - Short supporting copy explaining multi-model assessment.
   - Large URL input with paste affordance and scan button.
   - Helper text: “Check the URL before you sign in, pay, or share personal information.”
   - Privacy note explaining how submitted URLs are handled. Do not invent a retention promise.

3. **Bento feature grid**
   - Phishing & impersonation.
   - Domain and URL signals.
   - TLS certificate health.
   - Redirect behaviour.
   - Web security posture.
   - Community intelligence.
   Each tile has a concise description, a simple icon or abstract visual, and a subtle hover response.

4. **How the assessment works**
   - A horizontal or stacked sequence: Submit URL → Independent models → Evidence correlation → Trust score.
   - State clearly that models can disagree and that the score is an indicator, not a guarantee.

5. **About / motion strip section**
   - One continuous strip moving left-to-right and a second moving right-to-left.
   - Use short phrases such as “Inspect the signal”, “Verify the identity”, “Understand the risk”, “Share what you find”.
   - Keep the strips decorative and hide them from assistive technology if their content is repeated.
   - Respect `prefers-reduced-motion`; stop or simplify movement when requested.

6. **Threat intelligence preview**
   - Recent community submissions or aggregate activity.
   - Only show live counts, timestamps, or reports when supplied by the backend.
   - Demo content must carry a visible “Sample data” label.

7. **Footer**
   - About, methodology, privacy, responsible disclosure, contact.
   - Avoid dead links; hide links that are not implemented.

## 6. Scan experience

### URL input

- Accept `http://` and `https://` URLs.
- If a user enters a bare domain, offer to normalize it to `https://` and show the normalized value before scanning.
- Reject malformed URLs and unsupported schemes such as `javascript:`, `file:`, and `data:`.
- Do not fetch the submitted URL directly from frontend JavaScript.
- Display the hostname separately so users can spot misspellings and lookalike domains.
- Include clear, keyboard-accessible error messaging.

### Scan progress

Show meaningful stages, not a fake percentage that implies measured progress:

- Parsing URL and domain.
- Checking reputation signals.
- Reviewing phishing and impersonation indicators.
- Validating certificate information.
- Reviewing redirect and web-security signals.
- Correlating model results.

Progress animation is presentation only. Backend status must drive real progress when integrated. For the prototype, label the result as simulated.

### Results summary

The results screen contains:

- Trust Score: 0–100.
- Risk category: **Low risk**, **Caution**, **High risk**, or **Insufficient data**.
- One-sentence plain-language summary.
- Scanned hostname and timestamp.
- Clear “Demo assessment” label until real analysis is connected.
- Primary actions: “Scan another URL” and “View findings”.

Suggested score interpretation for the prototype:

| Score | Display category | Meaning |
|---:|---|---|
| 80–100 | Lower observed risk | No major warning signals in the available checks |
| 60–79 | Caution | Some signals need review |
| 30–59 | High risk | Multiple concerning signals detected |
| 0–29 | Critical risk | Strong indicators of malicious activity |
| Any | Insufficient data | Not enough reliable evidence to score |

A score must never override a critical confirmed finding. If the backend reports a confirmed malicious indicator, the UI should display the warning prominently even if the numeric score is higher.

### Model breakdown

Show each model as an independent result with:

- Model name.
- What it checks.
- Verdict: Clear / Suspicious / Malicious / Unknown / Error.
- Confidence, only if the backend defines and calibrates it.
- Evidence summary.
- Last checked time, if supplied.

Initial frontend model slots:

1. **Phishing & impersonation model** — suspicious page patterns, brand similarity, credential-harvesting indicators.
2. **URL & domain intelligence model** — hostname structure, domain age/reputation, lexical patterns, known threat feeds.
3. **TLS & certificate model** — certificate validity, hostname match, expiry, chain, issuer, transparency-related signals.
4. **Redirect analysis model** — redirect chain, unexpected destinations, URL shorteners, suspicious landing behaviour.
5. **Web security posture model** — safe, non-invasive checks for headers and exposed metadata.
6. **Collaborative intelligence model** — corroborated community reports and threat-feed matches.

These are product-facing categories, not a claim that the frontend contains trained models. Model names and outputs must come from the backend contract.

### Findings and evidence

- Group findings by severity: Critical, High, Medium, Low, Informational.
- Explain why each finding matters in one or two sentences.
- Show evidence provenance: model, feed, or check that produced it.
- Distinguish “not checked” from “passed”.
- Never reveal sensitive internal detection rules that would make evasion easier.
- Do not label a site “safe”; prefer “No major issues observed in checks performed”.

### User guidance

For suspicious or high-risk results, show practical guidance:
- Do not enter passwords, payment details, or one-time codes.
- Navigate to the organisation using a known bookmark or manually typed official address.
- Verify unexpected requests through an independent channel.
- Report the URL if the user believes it is malicious.

## 7. Trust score principles

The score is a summary, not a verdict of certainty.

- Score calculation belongs to the backend.
- Frontend displays the supplied score and score explanation.
- Missing model output must not be treated as a pass.
- Conflicting results must be visible.
- Critical confirmed indicators can trigger an override warning.
- Show the number of checks completed, skipped, and errored.
- Provide a “How is this score calculated?” disclosure.
- Avoid false precision: display an integer score, not several decimal places.

Suggested frontend payload fields:

- `score`: integer 0–100 or null.
- `riskLevel`: `low | caution | high | critical | insufficient_data`.
- `summary`: plain-language text.
- `models`: array of model results.
- `findings`: array of evidence-backed findings.
- `checkedAt`: ISO timestamp.
- `scanId`: opaque identifier.
- `isDemo`: boolean.
- `criticalOverride`: boolean.

## 8. Collaborative threat intelligence

The interface may include:
- Submit a suspicious URL for review.
- Report type: phishing, impersonation, malware, scam, suspicious redirect, other.
- Optional notes.
- Confirmation that the report was received.
- Community activity feed with moderation status.

Requirements:
- Explain what information is shared before submission.
- Do not publish personal information or reporter identity.
- Add rate limiting and abuse prevention in the backend.
- Community reports are signals, not proof; label unverified reports.
- Provide a correction or appeal route for false positives.

## 9. Visual direction

### Design concept

**Futuristic minimalism with soft, tactile surfaces.** The interface should feel like a thoughtfully engineered instrument, not a generic AI landing page.

- Main accent: `#367055`.
- Dark forest / graphite foundation with muted neutral text.
- Glass panels with restrained translucency, fine borders, and layered depth.
- Clay-inspired softness through rounded geometry, gentle inset shadows, and tactile controls.
- Avoid neon overload, purple/blue AI gradients, glowing orb clichés, excessive blur, and decorative “AI” labels.
- Use gradients only when subtle and derived from the accent and neutral palette.

### Suggested palette

| Token | Value | Use |
|---|---|---|
| Accent | `#367055` | Primary actions, focus, active states |
| Accent-soft | `#244B3A` | Secondary green surface |
| Background | `#0B100E` | Main page background |
| Surface | `#121A16` | Base panels |
| Glass | `rgba(24, 36, 29, 0.72)` | Translucent panels |
| Border | `rgba(190, 215, 198, 0.12)` | Fine panel outlines |
| Text-primary | `#E8EEE9` | Main text |
| Text-muted | `#9AA9A0` | Supporting text |
| Success | `#78B58D` | Positive signals |
| Warning | `#D7AA62` | Caution |
| Danger | `#D97878` | Malicious / critical |
| Info | `#91A9B7` | Informational |

Do not rely on color alone to communicate status. Pair status colors with labels and icons.

### Typography

Use a deliberate two-font system:
- **Primary / left-to-right:** `Manrope` or `Inter` for interface text, headings, numbers, and controls.
- **Secondary / right-to-left capable:** `Noto Sans Arabic` for RTL text support and selected editorial accents. If the intended second font is only for visual contrast rather than RTL language support, use `IBM Plex Mono` for technical metadata instead.

Use tabular numerals for the score and technical values. Keep body copy readable and avoid ultra-thin weights.

### Layout and motion

- Bento grid with varied card spans and consistent internal spacing.
- Large central scanner panel.
- Generous whitespace and a clear visual hierarchy.
- Fluid transitions with restrained spring-like easing.
- Clay-inspired hover states: slight lift, soft inset-to-raised transition, no exaggerated wobble.
- Left-to-right and right-to-left infinite strips in the About section.
- Pause strips on hover/focus where appropriate; respect reduced-motion preferences.
- Motion must not delay access to scan results.

## 10. Responsive behaviour

- Desktop: full navigation, wide scanner hero, 12-column bento grid.
- Tablet: 2-column feature grid; keep scanner full width.
- Mobile: single-column layout, full-width input and action, compact result cards, no horizontal overflow.
- Score visualization must remain legible at 320px viewport width.
- Motion strips may be reduced to static content on small screens or when reduced motion is enabled.

## 11. Accessibility

- Target WCAG 2.2 AA.
- Full keyboard operation and visible focus states.
- Semantic headings and landmarks.
- Accessible labels for inputs and buttons.
- Announce scan progress and completion with appropriate live regions.
- Ensure status is conveyed by text and icon, not color alone.
- Support zoom and reflow.
- Respect reduced-motion preferences.
- Maintain adequate contrast through glass surfaces; do not place text over busy decoration.

## 12. Frontend states

- Empty / ready.
- URL focused.
- Invalid URL.
- Normalization confirmation.
- Scanning.
- Scan complete.
- Partial results.
- Insufficient data.
- Scan failed / service unavailable.
- Demo mode.
- Report submitted.
- Clipboard action success / failure.

Every state needs a designed empty, loading, success, and error treatment.

## 13. Analytics events

Track only what is necessary and consistent with the privacy policy:

- `scan_started`
- `scan_completed`
- `scan_failed`
- `finding_expanded`
- `score_methodology_opened`
- `threat_report_submitted`

Avoid logging full URLs or query strings by default. If URL collection is required for security operations, document the purpose, access, retention, and consent model.

## 14. Acceptance criteria

- User can enter and validate a URL without a page reload.
- Unsupported schemes are rejected.
- Demo mode is visibly identified.
- Scan progress and all result states are implemented.
- Trust score and model-level verdicts are rendered from a typed data object.
- Unknown, skipped, and errored checks are distinct from passing checks.
- Critical findings are prominent and cannot be visually hidden by a high score.
- Findings include severity and evidence provenance.
- Bento layout adapts to desktop, tablet, and mobile.
- Both ticker directions work and respect reduced motion.
- Keyboard navigation, focus, contrast, and screen-reader labels are covered.
- No frontend-only check is represented as a real security assessment.
