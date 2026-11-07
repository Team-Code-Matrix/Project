# Frontend Skill Guide — TrustLens

## Purpose

This guide defines the implementation standards for the TrustLens frontend. It is intended for a developer or coding agent building the user interface from the PRD.

## 1. Experience principles

1. **Evidence before reassurance.** Never present a green score as a guarantee of safety.
2. **Clarity over spectacle.** Use motion and depth to guide attention, not to decorate every element.
3. **Honest states.** Demo, unknown, skipped, failed, and passed are different states.
4. **Progressive disclosure.** Show the summary first; let users expand technical detail.
5. **Accessible by default.** Motion, contrast, keyboard support, and semantic markup are part of the design, not later polish.

## 2. Visual language

### Colour

Use `#367055` as the only dominant accent. Build the rest of the interface from charcoal, forest, warm grey, and off-white.

Do not use the familiar blue-purple-pink AI gradient. Avoid arbitrary rainbow glows. Use danger and warning colors only for meaningful security states.

### Glass and clay surfaces

- Use translucent surfaces sparingly and keep text contrast high.
- Use a thin border and a restrained shadow to separate panels.
- Apply soft inset shadows to selected controls for a tactile, clay-inspired quality.
- Avoid making every component a floating pill.
- Keep blur modest; the page should remain crisp and performant.
- Prefer one strong scanner panel and a few supporting surfaces over layers of nested cards.

### Shape and spacing

- Use a consistent spacing scale, preferably multiples of 4 or 8.
- Use medium-to-large radii for primary panels and smaller radii for controls.
- Align card content to a shared grid.
- Let the bento layout create variety through span and proportion, not random card sizes.

## 3. Typography

Recommended pairing:
- `Manrope` for primary UI and display typography.
- `IBM Plex Mono` for hostnames, timestamps, model IDs, and compact technical metadata.
- Add `Noto Sans Arabic` as a proper RTL fallback if Arabic-language support is in scope.

Use:
- Strong, compact headings.
- Comfortable body line-height.
- Tabular numerals for trust scores.
- Uppercase labels sparingly.
- No long paragraphs in dense dashboard cards.

Do not fake right-to-left typography by merely right-aligning English text. Apply `dir="rtl"` to actual RTL content and test mixed-direction URLs carefully.

## 4. Component inventory

Build reusable components around the product language:

- `AppShell`
- `TopNavigation`
- `HeroScanner`
- `UrlInput`
- `ScanProgress`
- `TrustScore`
- `RiskBadge`
- `ModelResultCard`
- `ModelResultsGrid`
- `FindingList`
- `FindingDetail`
- `ScoreMethodology`
- `FeatureBentoGrid`
- `ProcessSteps`
- `MotionTicker`
- `ThreatIntelPreview`
- `ReportThreatDialog`
- `SiteFooter`
- `EmptyState`
- `ErrorState`

Keep business logic out of purely presentational components.

## 5. URL handling

- Parse with the platform `URL` API.
- Permit only `http:` and `https:`.
- Reject empty input, invalid hostnames, and unsupported protocols.
- Normalize a bare domain only after showing the proposed normalized URL to the user.
- Preserve the path and query string when parsing; do not silently strip meaningful URL components.
- Render user-submitted URLs as text, never as raw HTML.
- Do not use the browser to fetch the submitted target.
- Do not place secrets or credentials from a URL into analytics.
- Treat internationalized domain names carefully; show the normalized hostname and, where useful, its punycode representation to help reveal homograph attacks.

Suggested validation contract:

```ts
type UrlValidation =
  | { valid: true; normalizedUrl: string; hostname: string }
  | { valid: false; reason: "empty" | "malformed" | "unsupported_protocol" };
```

## 6. Frontend data contracts

Keep API types explicit. A suggested initial contract:

```ts
type RiskLevel =
  | "low"
  | "caution"
  | "high"
  | "critical"
  | "insufficient_data";

type ModelVerdict =
  | "clear"
  | "suspicious"
  | "malicious"
  | "unknown"
  | "error"
  | "skipped";

type FindingSeverity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "informational";

interface ModelResult {
  id: string;
  name: string;
  description: string;
  verdict: ModelVerdict;
  confidence?: number;
  summary: string;
  evidence: string[];
  checkedAt?: string;
}

interface Finding {
  id: string;
  title: string;
  severity: FindingSeverity;
  description: string;
  source: string;
  evidence?: string[];
  recommendation?: string;
}

interface ScanResult {
  scanId: string;
  submittedUrl: string;
  hostname: string;
  score: number | null;
  riskLevel: RiskLevel;
  summary: string;
  models: ModelResult[];
  findings: Finding[];
  checkedAt: string;
  isDemo: boolean;
  criticalOverride: boolean;
  checksCompleted: number;
  checksSkipped: number;
  checksErrored: number;
}
```

Validate API responses at the boundary before rendering them. Do not assume every model result is present.

## 7. Trust score presentation

- Render a score only when `score` is a valid integer from 0 to 100.
- If score is null, show “Not enough data” rather than zero.
- Show the risk label next to the score.
- Include a short explanation and a link or disclosure for methodology.
- Show completed, skipped, and errored check counts.
- If `criticalOverride` is true, display a high-priority warning above the score.
- Do not calculate or invent the score in the browser.
- Do not average model confidence values unless the backend explicitly defines that calculation.

## 8. Model result presentation

Each model card should communicate:
- What it checks.
- Its verdict in plain language.
- Whether the check ran successfully.
- One useful evidence summary.
- An expandable detail area when more evidence exists.

Use consistent iconography and text labels. “Unknown” must not look like “Clear”.

## 9. Motion and interaction

### Motion ticker

Implement two independent strips:
- Strip A moves left-to-right.
- Strip B moves right-to-left.

Duplicate the content sequence to create a seamless loop. Avoid visible gaps or jumps. Use CSS transforms rather than repeatedly changing layout properties.

Respect:

```css
@media (prefers-reduced-motion: reduce) {
  .motion-ticker-track {
    animation: none;
    transform: none;
  }
}
```

Also:
- Pause decorative motion when the page is hidden if the chosen framework supports visibility-aware behaviour.
- Keep ticker text non-interactive unless it represents real navigation.
- Mark repeated decorative content as hidden from assistive technology.

### Clay-inspired transitions

- Use small changes in elevation, scale, and shadow.
- Prefer 160–260ms for ordinary hover/focus transitions.
- Use spring motion only where it improves feedback.
- Avoid elastic movement on security alerts or critical warnings.
- Never make the user wait for an animation to read a result.

## 10. Responsive rules

- Start with mobile-safe component structure.
- Use CSS grid for bento cards.
- Keep the URL field and scan action usable on narrow screens.
- Allow long hostnames and evidence strings to wrap safely.
- Keep score visualization from forcing horizontal overflow.
- Test at 320px, 375px, 768px, 1024px, and wide desktop widths.

## 11. Accessibility checklist

- [ ] Every input has a programmatic label.
- [ ] Every action is keyboard operable.
- [ ] Focus indicators are visible on glass surfaces.
- [ ] Status uses text and icon as well as color.
- [ ] Scan updates are announced without excessive chatter.
- [ ] Dialogs trap and restore focus correctly.
- [ ] Reduced motion is respected.
- [ ] Text contrast remains sufficient on translucent panels.
- [ ] RTL text is tested with mixed-direction URLs and punctuation.
- [ ] Decorative ticker content is hidden from screen readers.

## 12. Frontend security checklist

- Never evaluate or execute submitted URLs.
- Never inject submitted content with `dangerouslySetInnerHTML` or equivalent.
- Encode user-controlled text when rendering.
- Do not fetch arbitrary URLs from the browser.
- Do not expose API secrets in client bundles.
- Do not trust model output as HTML.
- Treat threat-feed content and community reports as untrusted input.
- Use a backend proxy with SSRF protections for any server-side URL analysis.
- Ensure the backend blocks loopback, private, link-local, metadata, and otherwise restricted IP ranges; re-check after DNS resolution and redirects.
- Limit redirect depth, response size, timeouts, and supported protocols on the server.
- Keep intrusive scanning out of the frontend and require explicit authorisation for any active security testing.

## 13. Quality gates

Before merging:
- Type-check passes.
- Lint passes.
- URL validation tests pass.
- Loading, partial, empty, and error states are tested.
- Responsive layouts are reviewed.
- Reduced-motion mode is reviewed.
- Keyboard-only flow is tested.
- No sample data is shown without a demo label.
- No security claim exceeds the evidence supplied by the backend.
