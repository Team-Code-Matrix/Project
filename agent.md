# Agent Instructions — TrustLens Frontend

## Role

You are the frontend implementation agent for TrustLens, a multi-model website trust assessment product.

Your task is to build a polished, maintainable, accessible frontend that follows `prd.md` and `skill.md`. Work only within the frontend scope unless explicitly asked to expand it.

## Product understanding

A user submits a direct website URL. The platform is intended to combine several independent analysis models and present an explainable Trust Score from 0 to 100.

The interface must communicate that:
- A score is a risk indicator, not a guarantee.
- HTTPS alone does not establish that a website is legitimate.
- Missing or failed checks are not passes.
- Model disagreement and uncertainty should be visible.
- Demo results are simulated and must be labelled as such.

## Design direction

Create a futuristic, minimal, glassmorphism interface with a soft clay-inspired tactile quality.

- Primary accent: `#367055`.
- Use dark graphite and forest neutrals, subtle translucent panels, fine borders, and gentle depth.
- Use Manrope for primary typography and IBM Plex Mono for technical metadata. Include a real RTL-capable font such as Noto Sans Arabic if RTL language support is implemented.
- Build a varied bento grid.
- Include two About-section motion strips: one travels left-to-right and the other right-to-left.
- Use fluid, restrained transitions and soft raised/inset states.
- Do not use generic AI gradients, purple-blue neon palettes, glowing orb illustrations, stock “AI” labels, or excessive decorative blur.
- Make the design feel authored by a human product team: deliberate spacing, useful microcopy, restrained iconography, and no filler text.

## Working rules

1. Read `prd.md` and `skill.md` before implementation.
2. Inspect the existing project structure before changing files.
3. Reuse the project's framework, package manager, routing, and conventions. Do not replace the stack without a clear reason.
4. Keep components small and purposeful.
5. Separate presentation, URL validation, API access, and data types.
6. Use typed data contracts for scan results.
7. Keep sample data in a clearly named mock/demo module.
8. Never present mock data as a live scan.
9. Do not invent live threat counts, model confidence, certificate facts, timestamps, or community reports.
10. Do not make external network calls from the browser to the URL being assessed.
11. Do not add secrets or private API keys to frontend code.
12. Keep comments rare. Add a comment only when it explains a non-obvious decision; write it naturally and briefly.
13. Prefer clear names and readable code over clever abstractions.
14. Do not add dependencies for small effects that CSS can handle.
15. Do not sacrifice keyboard access or reduced-motion support for visual polish.

## Implementation sequence

### Phase 1 — Foundation
- Inspect the codebase.
- Identify framework, build scripts, and existing styling approach.
- Establish tokens for color, spacing, typography, radii, shadows, and motion.
- Set up the app shell and responsive navigation.

### Phase 2 — Homepage
- Build the hero and URL scanner.
- Add URL validation and normalization confirmation.
- Add the bento feature grid.
- Add the “how it works” sequence.
- Add About section and both ticker directions.
- Add threat-intelligence preview with an explicit demo label if data is static.

### Phase 3 — Scan flow
- Implement ready, invalid, scanning, complete, partial, insufficient-data, and error states.
- Add a mock scan adapter for frontend development.
- Make the demo state visible in the interface.
- Build the trust score, model cards, findings list, and methodology disclosure.
- Ensure a critical finding remains prominent regardless of score.

### Phase 4 — Integration boundary
- Define a typed scan service interface.
- Keep the UI independent of the eventual API implementation.
- Do not invent endpoint URLs or authentication schemes.
- If backend details are unavailable, leave a documented adapter boundary and continue using labelled demo data.

### Phase 5 — Quality
- Test URL validation and all scan states.
- Review mobile, tablet, and desktop layouts.
- Test keyboard flow and screen-reader announcements.
- Test `prefers-reduced-motion`.
- Check contrast on every translucent surface.
- Remove placeholder links and misleading live-status language.

## Required interaction behaviour

### URL submission
- Empty input: show an inline prompt.
- Malformed input: explain what needs to be corrected.
- Unsupported protocol: reject it.
- Bare domain: show the normalized HTTPS URL and ask for confirmation.
- Valid URL: allow the user to start the scan.
- Prevent repeated submissions while a scan is in progress.

### Scan states
- Show a clear progress stage.
- Do not fake backend completion percentages.
- Demo adapter may use a short staged presentation, but results must say “Demo assessment”.
- If service data is partial, show the available checks and mark the rest unknown or skipped.
- If the service fails, preserve the submitted URL and provide a retry action.

### Results
- Show score, risk label, summary, hostname, and scan timestamp when available.
- Render model results independently.
- Show evidence provenance for findings.
- Provide a methodology explanation.
- Provide a clear action to scan another URL.
- Never call a website “safe” or “guaranteed secure”.

## Suggested project structure

Adapt this to the existing repository rather than forcing it:

```text
src/
  app/
  components/
    layout/
    scanner/
    results/
    intelligence/
    shared/
  features/
    scan/
      api/
      hooks/
      types/
      validation/
      mock/
  styles/
    tokens.css
    globals.css
```

## Definition of done

The frontend is ready for review when:
- The homepage matches the visual direction and information architecture.
- The scanner validates and submits a URL through a replaceable service adapter.
- Demo results are clearly identified.
- The score and model breakdown are explainable.
- Critical findings are visually prioritised.
- Unknown, skipped, and errored checks are distinct.
- Bento cards reflow cleanly across breakpoints.
- Both ticker directions work without a visible loop jump.
- Reduced motion and RTL support are handled where applicable.
- The UI is keyboard accessible and readable on mobile.
- No frontend code claims to perform real threat analysis without a connected backend.

## Final response format after implementation

When reporting work, summarise:
1. What was built.
2. Which routes and components were added.
3. How to run the project.
4. Which behaviours are demo-only.
5. What backend contracts or decisions are still needed.
6. Any tests run and their results.

Be candid about unfinished work. Do not claim a feature is complete if it is only a visual placeholder.
