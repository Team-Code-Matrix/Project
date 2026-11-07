import React, { useRef, useEffect } from 'react';

export const InteractiveHeroPanel: React.FC = () => {
  const panelRef = useRef<HTMLDivElement>(null);
  const lightRef = useRef<HTMLDivElement>(null);
  const borderGlowRef = useRef<HTMLDivElement>(null);

  // Animation & interpolation refs (no React state re-renders during mouse move)
  const animFrameId = useRef<number | null>(null);
  const isHovered = useRef(false);
  const targetRotX = useRef(0);
  const targetRotY = useRef(0);
  const targetTransY = useRef(0);
  const targetScale = useRef(1);
  const currentRotX = useRef(0);
  const currentRotY = useRef(0);
  const currentTransY = useRef(0);
  const currentScale = useRef(1);

  useEffect(() => {
    // Only enable interactive 3D tilt if device supports fine hover pointer and user doesn't prefer reduced motion
    const hasFinePointer = window.matchMedia('(hover: hover) and (pointer: fine)').matches;
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    if (!hasFinePointer || prefersReducedMotion) {
      return;
    }

    const panel = panelRef.current;
    if (!panel) return;

    // Strict maximum rotation: ±1.0 degree (controlled, elegant)
    const MAX_TILT = 1.0;
    // Elevation lift and subtle scale
    const LIFT_PX = -3.0;
    const HOVER_SCALE = 1.002;

    const updateTilt = () => {
      // Smooth linear interpolation (lerp)
      const ease = 0.08;
      currentRotX.current += (targetRotX.current - currentRotX.current) * ease;
      currentRotY.current += (targetRotY.current - currentRotY.current) * ease;
      currentTransY.current += (targetTransY.current - currentTransY.current) * ease;
      currentScale.current += (targetScale.current - currentScale.current) * ease;

      if (panelRef.current) {
        panelRef.current.style.transform = `perspective(1200px) rotateX(${currentRotX.current.toFixed(
          3
        )}deg) rotateY(${currentRotY.current.toFixed(
          3
        )}deg) translateY(${currentTransY.current.toFixed(
          2
        )}px) scale(${currentScale.current.toFixed(4)}) translateZ(0)`;
      }

      const diffRotX = Math.abs(targetRotX.current - currentRotX.current);
      const diffRotY = Math.abs(targetRotY.current - currentRotY.current);
      const diffTransY = Math.abs(targetTransY.current - currentTransY.current);
      const diffScale = Math.abs(targetScale.current - currentScale.current);

      // Keep running while hovered or while easing back to rest position
      if (
        isHovered.current ||
        diffRotX > 0.003 ||
        diffRotY > 0.003 ||
        diffTransY > 0.01 ||
        diffScale > 0.0001
      ) {
        animFrameId.current = requestAnimationFrame(updateTilt);
      } else {
        // Fully settled back to 0 -> stop rAF loop (0 idle CPU usage)
        currentRotX.current = 0;
        currentRotY.current = 0;
        currentTransY.current = 0;
        currentScale.current = 1.0;
        if (panelRef.current) {
          panelRef.current.style.transform =
            'perspective(1200px) rotateX(0deg) rotateY(0deg) translateY(0px) scale(1) translateZ(0)';
        }
        animFrameId.current = null;
      }
    };

    const handleMouseMove = (e: MouseEvent) => {
      const rect = panel.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      // Normalized coordinates (-1 to 1)
      const normX = Math.max(-1, Math.min(1, (x - rect.width / 2) / (rect.width / 2)));
      const normY = Math.max(-1, Math.min(1, (y - rect.height / 2) / (rect.height / 2)));

      // Controlled physical tilt & floating elevation
      targetRotY.current = normX * MAX_TILT;
      targetRotX.current = -normY * MAX_TILT;
      targetTransY.current = LIFT_PX;
      targetScale.current = HOVER_SCALE;

      // Internal sepia projector illumination restricted strictly inside the hero panel
      if (lightRef.current) {
        lightRef.current.style.background = `radial-gradient(circle 420px at ${x}px ${y}px, rgba(181, 145, 91, 0.10) 0%, rgba(151, 116, 76, 0.055) 35%, rgba(112, 91, 68, 0.015) 65%, transparent 85%)`;
      }

      // Subtle sepia border hairline illumination
      if (borderGlowRef.current) {
        borderGlowRef.current.style.background = `radial-gradient(circle 260px at ${x}px ${y}px, rgba(181, 145, 91, 0.35) 0%, rgba(151, 116, 76, 0.12) 45%, transparent 70%)`;
      }

      // Start rAF if not currently running
      if (!animFrameId.current) {
        animFrameId.current = requestAnimationFrame(updateTilt);
      }
    };

    const handleMouseEnter = () => {
      isHovered.current = true;
      targetTransY.current = LIFT_PX;
      targetScale.current = HOVER_SCALE;
      if (lightRef.current) {
        lightRef.current.style.opacity = '1';
      }
      if (borderGlowRef.current) {
        borderGlowRef.current.style.opacity = '1';
      }
      if (!animFrameId.current) {
        animFrameId.current = requestAnimationFrame(updateTilt);
      }
    };

    const handleMouseLeave = () => {
      isHovered.current = false;
      // Target returns smoothly to rest position (0 rotation, 0 translation, scale 1.0)
      targetRotX.current = 0;
      targetRotY.current = 0;
      targetTransY.current = 0;
      targetScale.current = 1.0;

      // Fade out illumination smoothly over 450ms
      if (lightRef.current) {
        lightRef.current.style.opacity = '0';
      }
      if (borderGlowRef.current) {
        borderGlowRef.current.style.opacity = '0';
      }

      // Ensure rAF is running so it smoothly eases back to origin without snapping
      if (!animFrameId.current) {
        animFrameId.current = requestAnimationFrame(updateTilt);
      }
    };

    panel.addEventListener('mousemove', handleMouseMove);
    panel.addEventListener('mouseenter', handleMouseEnter);
    panel.addEventListener('mouseleave', handleMouseLeave);

    return () => {
      panel.removeEventListener('mousemove', handleMouseMove);
      panel.removeEventListener('mouseenter', handleMouseEnter);
      panel.removeEventListener('mouseleave', handleMouseLeave);
      if (animFrameId.current) {
        cancelAnimationFrame(animFrameId.current);
      }
    };
  }, []);

  return (
    <div className="w-full flex justify-center px-2 sm:px-4">
      {/* 
        3D Perspective Wrapper
        - Dimensions reduced by ~10% (max-w-[860px] vs old max-w-[960px])
        - Preserves perfect centering and fluid responsiveness
      */}
      <div
        ref={panelRef}
        className="w-full max-w-[860px] mb-6 text-left rounded-2xl relative select-none animate-hero-entrance"
        style={{
          transformStyle: 'preserve-3d',
          transform: 'perspective(1200px) rotateX(0deg) rotateY(0deg) translateY(0px) scale(1) translateZ(0)',
          willChange: 'transform',
        }}
      >
        {/* Interactive Border Glow Layer (1px perimeter highlight that follows cursor) */}
        <div
          ref={borderGlowRef}
          aria-hidden="true"
          className="absolute -inset-[1px] rounded-2xl pointer-events-none transition-opacity duration-500 opacity-0 z-0"
        />

        {/* Static Base Hairline Border (Preserved Thin Architectural Boundary) */}
        <div
          aria-hidden="true"
          className="absolute -inset-[1px] rounded-2xl border border-[rgba(120,135,124,0.3)] pointer-events-none z-0"
        />

        {/* 
          Inner Translucent Terminal Canvas:
          - Reduced opacity to bg-[#080B09]/45 and lightweight backdrop-blur-[3px]
          - Allows the interactive ASCII binary world map to be clearly visible through the panel
        */}
        <div className="relative rounded-2xl bg-[#080B09]/45 backdrop-blur-[3px] overflow-hidden shadow-[0_20px_50px_rgba(0,0,0,0.55)] z-10 border border-[rgba(120,135,124,0.18)]">
          {/* Soft Cursor-Following Internal Sepia Projector Glow (Confined Strictly to Hero Panel) */}
          <div
            ref={lightRef}
            aria-hidden="true"
            className="absolute inset-0 pointer-events-none transition-opacity duration-500 opacity-0 z-0"
          />

          {/* Technical Blueprint Header Metadata Row */}
          <div className="px-4 sm:px-5 py-2 sm:py-2.5 border-b border-[rgba(120,135,124,0.2)] flex flex-wrap items-center justify-between gap-2.5 text-xs font-mono text-[#78877C] bg-[#101713]/40 relative z-10">
            <div className="flex items-center gap-2.5 sm:gap-3">
              <span className="w-2 h-2 rounded-full bg-[#F3D081] shadow-[0_0_8px_#F3D081] animate-pulse" />
              <span className="text-[#E9E6DC] font-bold tracking-wider text-[11px] uppercase">
                SYS_SPEC: RFC-3986 // TS-2026-INGESTION
              </span>
              <span className="hidden md:inline text-[10px] text-[#78877C]">|</span>
              <span className="hidden md:inline text-[10px] text-[#B7C4B8] tracking-widest uppercase">
                CYBERSECURITY & WEB REPUTATION ENGINE
              </span>
            </div>
            <div className="flex items-center gap-3 text-[10px] font-mono tracking-wider">
              <span className="text-[#B7C4B8]">
                COORDS: <strong className="text-[#E9E6DC]">37.7749° N, 122.4194° W</strong>
              </span>
              <span className="text-[#F3D081] bg-[#141D18]/70 px-2 py-0.5 rounded border border-[#F3D081]/30 font-bold uppercase">
                06 ENGINES ACTIVE
              </span>
            </div>
          </div>

          {/* Main Grotesque Typography Block (Refined compact padding: ~10% reduction) */}
          <div className="p-4 sm:p-6 md:p-7 md:py-6 relative overflow-hidden z-10">
            <div className="space-y-1 max-w-4xl animate-hero-content">
              {/* Small-caps utilitarian section stamp */}
              <div className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-[0.15em] text-[#78877C] mb-2">
                <span className="px-1.5 py-0.5 rounded bg-[#141D18]/80 border border-[rgba(120,135,124,0.3)] text-[#F3D081] font-bold">
                  01 // THREAT DIRECTIVE
                </span>
                <span>MULTI-MODEL HEURISTIC MATRIX</span>
              </div>

              {/* Massive Grotesque Display Heading: 2 Rigid Lines, Tight Kerning & Leading */}
              <h1 className="swiss-hero-title">
                <span className="block text-[#E9E6DC] tracking-[-0.045em] sm:whitespace-nowrap">
                  NOT EVERY LINK
                </span>
                <div className="flex items-baseline gap-2.5 sm:gap-4 mt-0.5 sm:whitespace-nowrap flex-wrap sm:flex-nowrap">
                  <span className="text-[#E9E6DC] tracking-[-0.045em]">DESERVES</span>
                  <span
                    className="relative tracking-[-0.045em] inline-block font-extrabold select-none"
                    style={{
                      backgroundImage:
                        'linear-gradient(135deg, #D9B66F 0%, #F6D995 30%, #FFF0C2 52%, #D9B66F 72%, #C99B49 100%)',
                      WebkitBackgroundClip: 'text',
                      WebkitTextFillColor: 'transparent',
                      color: 'transparent',
                    }}
                  >
                    YOUR TRUST.
                    <span
                      aria-hidden="true"
                      className="absolute -bottom-1 left-0 right-0 h-[2.5px] md:h-[3px] rounded-full"
                      style={{
                        background:
                          'linear-gradient(90deg, #D9B66F 0%, #F6D995 35%, #FFF0C2 55%, #C99B49 100%)',
                        boxShadow: '0 1px 8px rgba(217, 182, 111, 0.28)',
                      }}
                    />
                  </span>
                </div>
              </h1>
            </div>

            {/* Subtitle & Structural Metadata Grid (Compact vertical spacing, ~10% reduction) */}
            <div className="mt-5 pt-4 border-t border-[rgba(120,135,124,0.2)] grid grid-cols-1 md:grid-cols-12 gap-4 md:gap-5 items-start animate-hero-meta">
              <div className="md:col-span-8">
                <p className="text-xs sm:text-sm md:text-[15px] text-[#B7C4B8] font-normal leading-relaxed tracking-normal max-w-xl">
                  Go beyond the lock icon. Analyse websites through multiple security intelligence models and understand the risks before you interact.
                </p>
              </div>
              <div className="md:col-span-4 flex flex-col gap-1.5 font-mono text-[11px] text-[#78877C] md:border-l md:border-[rgba(120,135,124,0.2)] md:pl-4">
                <div className="flex items-center justify-between">
                  <span className="uppercase tracking-wider text-[10px]">ANALYSIS LATENCY:</span>
                  <span className="text-[#F3D081] font-bold">&lt; 1400ms</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="uppercase tracking-wider text-[10px]">INSPECTION MODE:</span>
                  <span className="text-[#E9E6DC]">PASSIVE AIR-GAP</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="uppercase tracking-wider text-[10px]">VETO OVERRIDE:</span>
                  <span className="text-rose-400 font-bold">ZERO TOLERANCE</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

