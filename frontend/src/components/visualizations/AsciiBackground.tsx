import React, { useEffect, useRef } from 'react';

export interface AsciiBackgroundProps {
  className?: string;
  accentColor?: string; // Champagne Gold #F3D081
  ivoryColor?: string; // Ivory #E9E6DC
  desaturatedColor?: string; // Desaturated Green #78877C
  baseBgColor?: string; // Obsidian #080B09
  cursorRadius?: number; // Soft radial illumination radius in pixels
}

const OBSIDIAN_BG = '#080B09';

// Deterministic 32-bit integer hash to keep characters perfectly stable across frames
const getStableHash = (c: number, r: number, seed = 0): number => {
  let h = ((c * 374761393 + r * 668265263 + seed * 1274126177) ^ 0x5bf03635) >>> 0;
  h = Math.imul(h ^ (h >>> 13), 1274126177) >>> 0;
  return h;
};

// Five-tier character sets representing geographic density
const PALETTES = {
  // Tier 0: Deep Ocean - visually quiet, spacious, subtle maritime coordinate markers
  oceanDeep: [' ', ' ', ' ', ' ', ' ', '.', '.', ',', ':', '~', '-', '`'],
  // Tier 1: Coastal Ocean / Shelf - subtle punctuation transition
  oceanCoast: ['.', ':', '~', '+', '-', '/', '=', '.'],
  // Tier 2: Coastline - clear contour boundaries without artificial thick borders
  coastline: ['+', '=', '~', ':', ';', '/', '\\', '|', '[', ']', '(', ')', '<', '>', '^', 'v', '*'],
  // Tier 3: Continental Landmass - telemetry alphanumeric, symbols
  landMid: ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'c', 'e', 'k', 'm', 'n', 'o', 'r', 's', 'u', 'x', 'z', '#', '%', '*', '='],
  // Tier 4: Core Inland - dense cybersecurity data glyphs
  landCore: ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'K', 'M', 'N', 'P', 'R', 'S', 'T', 'W', 'X', 'Y', 'Z', '@', '#', '%', '&', '$', '8', '9'],
};

const getTierChar = (tier: number, c: number, r: number): string => {
  let palette: string[];
  switch (tier) {
    case 0:
      palette = PALETTES.oceanDeep;
      break;
    case 1:
      palette = PALETTES.oceanCoast;
      break;
    case 2:
      palette = PALETTES.coastline;
      break;
    case 3:
      palette = PALETTES.landMid;
      break;
    case 4:
    default:
      palette = PALETTES.landCore;
      break;
  }
  return palette[getStableHash(c, r) % palette.length];
};

// Base resting colors - thin, muted, and non-distracting
const getTierBaseColor = (tier: number): string => {
  switch (tier) {
    case 0: // Deep ocean - very faint whisper
      return 'rgba(120, 135, 124, 0.05)';
    case 1: // Coastal ocean
      return 'rgba(120, 135, 124, 0.12)';
    case 2: // Coastline - subtle muted sage & warm tint
      return 'rgba(183, 196, 184, 0.38)';
    case 3: // Continental landmass - soft ivory
      return 'rgba(233, 230, 220, 0.28)';
    case 4: // Core inland - refined ivory with warm tone
      return 'rgba(233, 230, 220, 0.38)';
    default:
      return 'rgba(120, 135, 124, 0.05)';
  }
};

// Illuminated colors for the restrained background ASCII map cursor scanning effect:
// Combines muted champagne gold, dark olive, subtle sepia, and forest-green tones.
const getIlluminatedColor = (tier: number, intensity: number): string => {
  const isLand = tier >= 2;

  if (isLand) {
    if (tier === 2) {
      // Coastline contour - recognizable silhouette definition
      if (intensity >= 0.50) {
        // High intensity: Muted warm champagne gold with subtle sepia
        const a = 0.32 + intensity * 0.36; // max ~0.68
        return `rgba(215, 186, 130, ${a.toFixed(3)})`;
      } else if (intensity >= 0.20) {
        // Mid intensity: Dark olive-sage
        const a = 0.24 + intensity * 0.28; // ~0.30 - 0.38
        return `rgba(175, 188, 155, ${a.toFixed(3)})`;
      } else {
        // Outer falloff: Soft sage contour
        const a = 0.16 + intensity * 0.22; // ~0.16 - 0.20
        return `rgba(183, 196, 184, ${a.toFixed(3)})`;
      }
    } else {
      // Continental Landmass (tier 3) & Core Inland (tier 4)
      if (intensity >= 0.50) {
        // High intensity: Refined brushed champagne gold & sepia
        const a = 0.30 + intensity * 0.38; // max ~0.68
        return `rgba(224, 198, 142, ${a.toFixed(3)})`;
      } else if (intensity >= 0.20) {
        // Mid intensity: Dark olive-tinted champagne / sepia
        const a = 0.22 + intensity * 0.26; // ~0.27 - 0.35
        return `rgba(185, 180, 145, ${a.toFixed(3)})`;
      } else {
        // Outer falloff: Subtle ivory & forest-green tone
        const a = 0.16 + intensity * 0.20; // ~0.16 - 0.20
        return `rgba(165, 180, 165, ${a.toFixed(3)})`;
      }
    }
  } else {
    // Ocean (tier 0 & 1) - quiet maritime coordinate space, subtle scanning highlight
    if (tier === 1) {
      // Coastal Ocean / Shelf
      if (intensity >= 0.45) {
        const a = 0.14 + intensity * 0.22; // max ~0.36
        return `rgba(155, 172, 148, ${a.toFixed(3)})`;
      } else {
        const a = 0.08 + intensity * 0.14; // max ~0.22
        return `rgba(130, 148, 134, ${a.toFixed(3)})`;
      }
    } else {
      // Deep Ocean
      if (intensity >= 0.45) {
        const a = 0.10 + intensity * 0.18; // max ~0.28
        return `rgba(142, 158, 140, ${a.toFixed(3)})`;
      } else {
        const a = 0.06 + intensity * 0.10; // max ~0.16
        return `rgba(125, 140, 128, ${a.toFixed(3)})`;
      }
    }
  }
};

// Procedural fallback continental mask function (ensures recognizable continents on frame 0)
const isProceduralLand = (u: number, v: number): boolean => {
  // North America
  if (u >= 0.08 && u <= 0.30 && v >= 0.18 && v <= 0.52) {
    if (u < 0.16 && v > 0.44) return false;
    return true;
  }
  // Greenland
  if (u >= 0.28 && u <= 0.38 && v >= 0.08 && v <= 0.22) return true;
  // South America
  if (u >= 0.22 && u <= 0.36 && v >= 0.48 && v <= 0.84) {
    if (u < 0.26 && v > 0.75) return false;
    return true;
  }
  // Europe
  if (u >= 0.44 && u <= 0.56 && v >= 0.16 && v <= 0.38) {
    if (u > 0.46 && u < 0.52 && v > 0.34) return false;
    return true;
  }
  // Africa
  if (u >= 0.43 && u <= 0.59 && v >= 0.38 && v <= 0.78) {
    if (u < 0.48 && v > 0.65) return false;
    return true;
  }
  // Madagascar
  if (u >= 0.58 && u <= 0.62 && v >= 0.62 && v <= 0.74) return true;
  // Eurasia / Asia
  if (u >= 0.56 && u <= 0.88 && v >= 0.14 && v <= 0.52) {
    return true;
  }
  // Japan / Korea
  if (u >= 0.83 && u <= 0.89 && v >= 0.26 && v <= 0.40) return true;
  // Southeast Asia / Indonesia / Philippines
  if (u >= 0.72 && u <= 0.88 && v >= 0.50 && v <= 0.64) return true;
  // Australia & New Zealand
  if (u >= 0.76 && u <= 0.88 && v >= 0.64 && v <= 0.84) return true;
  if (u >= 0.88 && u <= 0.94 && v >= 0.74 && v <= 0.86) return true;

  return false;
};

export const AsciiBackground: React.FC<AsciiBackgroundProps> = React.memo(
  ({
    className = '',
    baseBgColor = OBSIDIAN_BG,
    cursorRadius = 260,
  }) => {
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const animFrameRef = useRef<number | null>(null);
    const resizeTimeoutRef = useRef<number | null>(null);

    // Physical mouse target vs smoothly eased current position
    const mouseTargetRef = useRef<{ x: number; y: number; active: boolean }>({
      x: -9999,
      y: -9999,
      active: false,
    });

    const mouseCurrentRef = useRef<{ x: number; y: number; active: boolean; alpha: number }>({
      x: -9999,
      y: -9999,
      active: false,
      alpha: 0,
    });

    // Reference to hero panel bounding box for strict interaction isolation
    const heroRectRef = useRef<DOMRect | null>(null);

    // Cached map data & offscreen pre-rendered static layer
    const mapImageRef = useRef<HTMLImageElement | null>(null);
    const baseCanvasRef = useRef<HTMLCanvasElement | null>(null);
    const gridStateRef = useRef<{
      cols: number;
      rows: number;
      charWidth: number;
      charHeight: number;
      tiers: Uint8Array | null;
      width: number;
      height: number;
    }>({
      cols: 0,
      rows: 0,
      charWidth: 7.0,
      charHeight: 12.0,
      tiers: null,
      width: 0,
      height: 0,
    });

    useEffect(() => {
      let isMounted = true;
      const canvas = canvasRef.current;
      if (!canvas) return;

      const ctx = canvas.getContext('2d', { alpha: false });
      if (!ctx) return;

      const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      const hasFinePointer = window.matchMedia('(hover: hover) and (pointer: fine)').matches;

      // 1. Build or re-build base offscreen canvas with recognizable ASCII world map
      const rebuildBaseCanvas = () => {
        if (!canvas || !isMounted) return;

        const dpr = Math.min(window.devicePixelRatio || 1, 2);
        const w = window.innerWidth;
        const h = window.innerHeight;

        canvas.width = Math.floor(w * dpr);
        canvas.height = Math.floor(h * dpr);
        canvas.style.width = `${w}px`;
        canvas.style.height = `${h}px`;

        ctx.setTransform(1, 0, 0, 1, 0, 0);
        ctx.scale(dpr, dpr);

        const isMobile = w < 768;
        const charWidth = isMobile ? 8.5 : w > 1440 ? 7.2 : 6.8;
        const charHeight = isMobile ? 13.5 : 12.0;
        const cols = Math.floor(w / charWidth);
        const rows = Math.floor(h / charHeight);

        // Aspect ratio preservation for true geographic silhouettes
        // SVG world map viewBox is 950 x 620 (1.532 aspect ratio)
        const mapRatio = 950 / 620;
        let mapWidth = w * 0.94;
        let mapHeight = mapWidth / mapRatio;
        if (mapHeight > h * 1.05) {
          mapHeight = h * 0.95;
          mapWidth = mapHeight * mapRatio;
        }

        const mapX = (w - mapWidth) / 2;
        const mapY = (h - mapHeight) / 2 + h * 0.015;

        // Sample landmass raster data
        const rawLand = new Uint8Array(cols * rows);

        const img = mapImageRef.current;
        let sampleData: Uint8ClampedArray | null = null;
        const sampleW = 950;
        const sampleH = 620;

        if (img && img.complete && img.naturalWidth > 0) {
          const sampleCanvas = document.createElement('canvas');
          sampleCanvas.width = sampleW;
          sampleCanvas.height = sampleH;
          const sCtx = sampleCanvas.getContext('2d', { willReadFrequently: true });
          if (sCtx) {
            sCtx.clearRect(0, 0, sampleW, sampleH);
            sCtx.drawImage(img, 0, 0, sampleW, sampleH);
            try {
              sampleData = sCtx.getImageData(0, 0, sampleW, sampleH).data;
            } catch {
              sampleData = null;
            }
          }
        }

        // Pass 1: Binary land/water determination with box-filtering for islands
        for (let r = 0; r < rows; r++) {
          const screenY = r * charHeight + charHeight / 2;
          const relY = screenY - mapY;

          for (let c = 0; c < cols; c++) {
            const screenX = c * charWidth + charWidth / 2;
            const relX = screenX - mapX;
            const idx = r * cols + c;

            if (relX < 0 || relX >= mapWidth || relY < 0 || relY >= mapHeight) {
              rawLand[idx] = 0;
              continue;
            }

            const u = relX / mapWidth;
            const v = relY / mapHeight;

            if (sampleData) {
              const sx = Math.floor(u * sampleW);
              const sy = Math.floor(v * sampleH);
              const sIdx = (sy * sampleW + sx) * 4;

              // Check sampled pixel or immediate 2x2 neighborhood to ensure small islands are captured
              let isLandPixel = sampleData[sIdx + 3] > 64;
              if (!isLandPixel && sx + 1 < sampleW && sy + 1 < sampleH) {
                const sIdx2 = (sy * sampleW + (sx + 1)) * 4;
                const sIdx3 = ((sy + 1) * sampleW + sx) * 4;
                if (sampleData[sIdx2 + 3] > 90 || sampleData[sIdx3 + 3] > 90) {
                  isLandPixel = true;
                }
              }
              rawLand[idx] = isLandPixel ? 1 : 0;
            } else {
              rawLand[idx] = isProceduralLand(u, v) ? 1 : 0;
            }
          }
        }

        // Pass 2: Five-tier classification (Deep Ocean, Coastal Water, Coastline, Mid Land, Core Inland)
        const tiers = new Uint8Array(cols * rows);

        for (let r = 0; r < rows; r++) {
          for (let c = 0; c < cols; c++) {
            const idx = r * cols + c;
            const isLand = rawLand[idx] === 1;

            if (isLand) {
              let isBoundary = false;
              let landNeighborCount = 0;

              for (let dr = -1; dr <= 1; dr++) {
                for (let dc = -1; dc <= 1; dc++) {
                  if (dr === 0 && dc === 0) continue;
                  const nr = r + dr;
                  const nc = c + dc;
                  if (nr < 0 || nr >= rows || nc < 0 || nc >= cols || rawLand[nr * cols + nc] === 0) {
                    isBoundary = true;
                  } else {
                    landNeighborCount++;
                  }
                }
              }

              if (isBoundary) {
                tiers[idx] = 2; // Coastline
              } else if (landNeighborCount >= 7) {
                tiers[idx] = 4; // Core Inland
              } else {
                tiers[idx] = 3; // Mid Land
              }
            } else {
              // Ocean: check if close to coast
              let nearCoast = false;
              for (let dr = -1; dr <= 1; dr++) {
                for (let dc = -1; dc <= 1; dc++) {
                  const nr = r + dr;
                  const nc = c + dc;
                  if (nr >= 0 && nr < rows && nc >= 0 && nc < cols && rawLand[nr * cols + nc] === 1) {
                    nearCoast = true;
                    break;
                  }
                }
                if (nearCoast) break;
              }
              tiers[idx] = nearCoast ? 1 : 0; // Coastal Water vs Deep Ocean
            }
          }
        }

        gridStateRef.current = {
          cols,
          rows,
          charWidth,
          charHeight,
          tiers,
          width: w,
          height: h,
        };

        // Pre-render static base layer onto offscreen canvas (Zero runtime overhead during idle)
        const offCanvas = document.createElement('canvas');
        offCanvas.width = Math.floor(w * dpr);
        offCanvas.height = Math.floor(h * dpr);
        const offCtx = offCanvas.getContext('2d', { alpha: false });

        if (offCtx) {
          offCtx.setTransform(1, 0, 0, 1, 0, 0);
          offCtx.scale(dpr, dpr);

          // Deep Obsidian Base
          offCtx.fillStyle = baseBgColor;
          offCtx.fillRect(0, 0, w, h);

          // Thinner, non-bold monospace font for clean, subtle readability
          offCtx.font = '300 9.5px "JetBrains Mono", "Fira Code", "IBM Plex Mono", Menlo, Consolas, monospace';
          offCtx.textBaseline = 'middle';
          offCtx.textAlign = 'center';

          for (let r = 0; r < rows; r++) {
            const py = r * charHeight + charHeight / 2;
            for (let c = 0; c < cols; c++) {
              const px = c * charWidth + charWidth / 2;
              const tier = tiers[r * cols + c];
              const char = getTierChar(tier, c, r);

              if (char === ' ') continue;

              offCtx.fillStyle = getTierBaseColor(tier);
              offCtx.fillText(char, px, py);
            }
          }

          baseCanvasRef.current = offCanvas;
        }

        // Draw static world map canvas to screen
        renderFrame();
      };

      // 2. High-performance draw function (renders clean static world map + restrained cursor scanning effect outside hero panel)
      const renderFrame = () => {
        if (!ctx || !canvas) return;
        const baseCanvas = baseCanvasRef.current;
        const grid = gridStateRef.current;
        if (!baseCanvas || !grid.tiers) return;

        // Draw static pre-rendered base layer in a single GPU drawImage call (0.1ms)
        ctx.drawImage(baseCanvas, 0, 0, grid.width, grid.height);

        const current = mouseCurrentRef.current;
        const target = mouseTargetRef.current;

        // Smooth position lerp
        const lerpPos = 0.12;
        current.x += (target.x - current.x) * lerpPos;
        current.y += (target.y - current.y) * lerpPos;

        // Smooth alpha fade
        const targetAlpha = target.active ? 1.0 : 0.0;
        const lerpAlpha = 0.09;
        current.alpha += (targetAlpha - current.alpha) * lerpAlpha;

        const isMoving =
          Math.abs(target.x - current.x) > 0.4 ||
          Math.abs(target.y - current.y) > 0.4 ||
          Math.abs(targetAlpha - current.alpha) > 0.005;

        // Render soft radial scanning illumination strictly OUTSIDE the hero panel
        if (current.alpha > 0.008 && current.x >= -cursorRadius && current.y >= -cursorRadius) {
          const cx = current.x;
          const cy = current.y;
          const R = cursorRadius;
          const R2 = R * R;
          const charW = grid.charWidth;
          const charH = grid.charHeight;
          const heroRect = heroRectRef.current;

          // A. Soft, feathered ambient radial aura (muted sepia / dark olive / forest green)
          // Uses evenodd clipping to guarantee ZERO background light leaks into the hero panel
          ctx.save();
          if (heroRect) {
            ctx.beginPath();
            ctx.rect(0, 0, grid.width, grid.height);
            // Hero panel has rounded-2xl (16px border-radius)
            if (typeof (ctx as any).roundRect === 'function') {
              (ctx as any).roundRect(heroRect.left, heroRect.top, heroRect.width, heroRect.height, 16);
            } else {
              ctx.rect(heroRect.left, heroRect.top, heroRect.width, heroRect.height);
            }
            ctx.clip('evenodd');
          }

          const radGrad = ctx.createRadialGradient(cx, cy, 0, cx, cy, R * 1.15);
          radGrad.addColorStop(0, `rgba(181, 145, 91, ${(0.028 * current.alpha).toFixed(4)})`);
          radGrad.addColorStop(0.35, `rgba(135, 140, 105, ${(0.018 * current.alpha).toFixed(4)})`);
          radGrad.addColorStop(0.70, `rgba(90, 115, 95, ${(0.009 * current.alpha).toFixed(4)})`);
          radGrad.addColorStop(1, 'rgba(8, 11, 9, 0)');

          ctx.fillStyle = radGrad;
          ctx.beginPath();
          ctx.arc(cx, cy, R * 1.15, 0, Math.PI * 2);
          ctx.fill();
          ctx.restore();

          // B. Character-level illumination within bounding box
          const minCol = Math.max(0, Math.floor((cx - R) / charW));
          const maxCol = Math.min(grid.cols, Math.ceil((cx + R) / charW));
          const minRow = Math.max(0, Math.floor((cy - R) / charH));
          const maxRow = Math.min(grid.rows, Math.ceil((cy + R) / charH));

          ctx.font = '300 9.5px "JetBrains Mono", "Fira Code", "IBM Plex Mono", Menlo, Consolas, monospace';
          ctx.textBaseline = 'middle';
          ctx.textAlign = 'center';

          const now = performance.now() * 0.0025;

          for (let r = minRow; r < maxRow; r++) {
            const py = r * charH + charH / 2;
            const inHeroY = heroRect ? py >= heroRect.top && py <= heroRect.bottom : false;
            const dy = py - cy;
            const dy2 = dy * dy;

            for (let c = minCol; c < maxCol; c++) {
              const px = c * charW + charW / 2;

              // Strict isolation: NEVER illuminate inside the hero panel
              if (inHeroY && heroRect && px >= heroRect.left && px <= heroRect.right) {
                continue;
              }

              const dx = px - cx;
              const dist2 = dx * dx + dy2;

              if (dist2 < R2) {
                const dist = Math.sqrt(dist2);
                const norm = dist / R; // 0 (center) to 1 (outer edge)

                // Smooth cubic falloff curve fading smoothly to pure zero at edge with continuous derivative
                const t = 1 - norm;
                const smoothT = t * t * (3 - 2 * t);
                let intensity = Math.pow(smoothT, 1.5) * current.alpha;

                if (intensity > 0.01) {
                  const tier = grid.tiers[r * grid.cols + c];
                  const char = getTierChar(tier, c, r);
                  if (char === ' ') continue;

                  // Subtle scanning wave response when cursor passes over land
                  if (tier >= 2) {
                    const wave = Math.sin(dist * 0.04 - now * 2) * 0.06;
                    intensity = Math.max(0, Math.min(1, intensity + wave * intensity));
                  }

                  ctx.fillStyle = getIlluminatedColor(tier, intensity);
                  ctx.fillText(char, px, py);
                }
              }
            }
          }
        }

        // Loop management: only keep running if motion or fade is active
        if (isMoving && (current.alpha > 0.005 || target.active)) {
          animFrameRef.current = requestAnimationFrame(renderFrame);
        } else {
          animFrameRef.current = null;
        }
      };

      // 3. Request-frame scheduler
      const scheduleRender = () => {
        if (animFrameRef.current === null) {
          animFrameRef.current = requestAnimationFrame(renderFrame);
        }
      };

      // 4. Mouse event listeners with hero panel boundary detection
      const handleMouseMove = (e: MouseEvent) => {
        const heroEl = document.getElementById('hero-interactive-panel');
        let isOverHero = false;

        if (heroEl) {
          const r = heroEl.getBoundingClientRect();
          heroRectRef.current = r;
          // Check if cursor is inside hero panel (with 2px padding for seamless boundary handoff)
          if (
            e.clientX >= r.left - 2 &&
            e.clientX <= r.right + 2 &&
            e.clientY >= r.top - 2 &&
            e.clientY <= r.bottom + 2
          ) {
            isOverHero = true;
          }
        }

        if (isOverHero) {
          // Cursor entered hero panel: smoothly transition background map illumination to 0
          mouseTargetRef.current.active = false;
        } else {
          // Cursor is on background: restore map scanning illumination
          mouseTargetRef.current = {
            x: e.clientX,
            y: e.clientY,
            active: true,
          };
        }
        scheduleRender();
      };

      const handleMouseLeave = () => {
        mouseTargetRef.current.active = false;
        scheduleRender();
      };

      const handleScroll = () => {
        const heroEl = document.getElementById('hero-interactive-panel');
        if (heroEl) {
          heroRectRef.current = heroEl.getBoundingClientRect();
        }
      };

      // 5. Debounced resize listener
      const handleResize = () => {
        const heroEl = document.getElementById('hero-interactive-panel');
        if (heroEl) {
          heroRectRef.current = heroEl.getBoundingClientRect();
        }
        if (resizeTimeoutRef.current !== null) {
          window.clearTimeout(resizeTimeoutRef.current);
        }
        resizeTimeoutRef.current = window.setTimeout(() => {
          rebuildBaseCanvas();
          resizeTimeoutRef.current = null;
        }, 150);
      };

      if (!prefersReducedMotion && hasFinePointer) {
        window.addEventListener('mousemove', handleMouseMove, { passive: true });
        window.addEventListener('mouseleave', handleMouseLeave, { passive: true });
      }
      window.addEventListener('scroll', handleScroll, { passive: true });
      window.addEventListener('resize', handleResize, { passive: true });

      // 6. Load accurate high-fidelity world map SVG
      const img = new Image();
      img.src = '/world-map-accurate.svg';
      img.crossOrigin = 'anonymous';
      img.onload = () => {
        if (!isMounted) return;
        mapImageRef.current = img;
        rebuildBaseCanvas();
      };
      img.onerror = () => {
        if (!isMounted) return;
        rebuildBaseCanvas();
      };

      // Initial build with procedural fallback if SVG hasn't completed loading yet
      rebuildBaseCanvas();

      // 7. Cleanup on unmount (strict memory leak prevention)
      return () => {
        isMounted = false;
        if (animFrameRef.current !== null) {
          cancelAnimationFrame(animFrameRef.current);
          animFrameRef.current = null;
        }
        if (resizeTimeoutRef.current !== null) {
          window.clearTimeout(resizeTimeoutRef.current);
          resizeTimeoutRef.current = null;
        }
        if (!prefersReducedMotion && hasFinePointer) {
          window.removeEventListener('mousemove', handleMouseMove);
          window.removeEventListener('mouseleave', handleMouseLeave);
        }
        window.removeEventListener('scroll', handleScroll);
        window.removeEventListener('resize', handleResize);

        if (ctx && canvas) {
          ctx.clearRect(0, 0, canvas.width, canvas.height);
        }
        baseCanvasRef.current = null;
        mapImageRef.current = null;
      };
    }, [baseBgColor, cursorRadius]);

    return (
      <div
        aria-hidden="true"
        className={`fixed inset-0 pointer-events-none select-none z-0 overflow-hidden ${className}`}
        style={{
          backgroundColor: baseBgColor,
        }}
      >
        <canvas ref={canvasRef} className="block w-full h-full" />
      </div>
    );
  }
);

AsciiBackground.displayName = 'AsciiBackground';
