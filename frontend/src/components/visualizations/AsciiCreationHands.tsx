import React, { useEffect, useRef, useState } from 'react';

export interface AsciiCreationHandsProps {
  className?: string;
  accentColor?: string; // Champagne Gold #F3D081
  ivoryColor?: string; // Ivory #E9E6DC
  sageColor?: string; // Muted Sage #B7C4B8
  opacity?: number;
  showOverlays?: boolean;
  enableInteractiveGlow?: boolean;
}

const GOLD_HEX = '#F3D081';

export const AsciiCreationHands: React.FC<AsciiCreationHandsProps> = ({
  className = '',
  accentColor = GOLD_HEX,
  opacity = 0.95,
  showOverlays = true,
  enableInteractiveGlow = true,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const mousePosRef = useRef<{ x: number; y: number; active: boolean }>({
    x: -9999,
    y: -9999,
    active: false,
  });

  const [imageLoaded, setImageLoaded] = useState(false);
  const imageRef = useRef<HTMLImageElement | null>(null);

  // Load the ultra-high-definition halftone master reference image
  useEffect(() => {
    let isMounted = true;
    const img = new Image();
    img.src = '/creation-hands-halftone-master.png';
    img.crossOrigin = 'anonymous';

    img.onload = () => {
      if (!isMounted) return;
      imageRef.current = img;
      setImageLoaded(true);
    };

    img.onerror = () => {
      // Fallback path
      const fallbackImg = new Image();
      fallbackImg.src = '/ascii-hands-reference.jpg';
      fallbackImg.crossOrigin = 'anonymous';
      fallbackImg.onload = () => {
        if (!isMounted) return;
        imageRef.current = fallbackImg;
        setImageLoaded(true);
      };
      fallbackImg.onerror = () => {
        if (isMounted) setImageLoaded(true);
      };
    };

    return () => {
      isMounted = false;
      img.onload = null;
      img.onerror = null;
    };
  }, []);

  // Main canvas render loop
  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const ctx = canvas.getContext('2d', { alpha: true });
    if (!ctx) return;

    let animationFrameId: number;
    let isVisible = true;
    let rotationAngle = 0;
    let waveformPhase = 0;
    let lastRenderTime = 0;
    const TARGET_FPS = 30;
    const FRAME_INTERVAL = 1000 / TARGET_FPS;

    const prefersReducedMotion = window.matchMedia(
      '(prefers-reduced-motion: reduce)'
    ).matches;

    // High-DPI scaling
    const handleResize = () => {
      if (!canvas || !container) return;
      const rect = container.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);

      canvas.width = Math.floor(rect.width * dpr);
      canvas.height = Math.floor(rect.height * dpr);
      canvas.style.width = `${rect.width}px`;
      canvas.style.height = `${rect.height}px`;

      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.scale(dpr, dpr);
    };

    const resizeObserver = new ResizeObserver(() => {
      handleResize();
      if (prefersReducedMotion) {
        renderFrame(0);
      }
    });
    resizeObserver.observe(container);
    handleResize();

    const intersectionObserver = new IntersectionObserver(
      (entries) => {
        const [entry] = entries;
        isVisible = entry.isIntersecting;
      },
      { threshold: 0.05 }
    );
    intersectionObserver.observe(container);

    const handleMouseMove = (e: MouseEvent) => {
      if (!enableInteractiveGlow || !container) return;
      const rect = container.getBoundingClientRect();
      mousePosRef.current = {
        x: e.clientX - rect.left,
        y: e.clientY - rect.top,
        active: true,
      };
    };

    const handleMouseLeave = () => {
      mousePosRef.current.active = false;
    };

    window.addEventListener('mousemove', handleMouseMove, { passive: true });
    window.addEventListener('mouseleave', handleMouseLeave);

    // Render Frame Function
    const renderFrame = (_timestamp: number) => {
      if (!ctx || !canvas || !container) return;

      const rect = container.getBoundingClientRect();
      const width = rect.width;
      const height = rect.height;

      if (width <= 0 || height <= 0) return;

      ctx.clearRect(0, 0, width, height);

      const img = imageRef.current;

      if (img && img.complete && img.naturalWidth > 0) {
        // Full-bleed cover alignment:
        // Guarantees left arm crosses x = 0 (left edge) and right arm crosses x = width (right edge)
        const scale = Math.max(width / img.naturalWidth, height / img.naturalHeight);
        const drawW = img.naturalWidth * scale;
        const drawH = img.naturalHeight * scale;
        const drawX = (width - drawW) / 2;
        const drawY = (height - drawH) * 0.44; // Position hands gracefully in upper hero behind title

        ctx.drawImage(img, drawX, drawY, drawW, drawH);

        // Subtle Champagne Gold glow filter over the clean white halftone dots
        ctx.save();
        ctx.globalCompositeOperation = 'screen';
        ctx.fillStyle = 'rgba(243, 208, 129, 0.10)';
        ctx.fillRect(0, 0, width, height);
        ctx.restore();

        // Interactive mouse spotlight illumination
        const mouse = mousePosRef.current;
        if (mouse.active && enableInteractiveGlow) {
          ctx.save();
          ctx.globalCompositeOperation = 'screen';
          const grad = ctx.createRadialGradient(
            mouse.x,
            mouse.y,
            0,
            mouse.x,
            mouse.y,
            240
          );
          grad.addColorStop(0, 'rgba(243, 208, 129, 0.32)');
          grad.addColorStop(0.5, 'rgba(243, 208, 129, 0.10)');
          grad.addColorStop(1, 'rgba(243, 208, 129, 0)');
          ctx.fillStyle = grad;
          ctx.fillRect(0, 0, width, height);
          ctx.restore();
        }
      } else {
        // Clean circular dot-matrix fallback (NO ASCII text letters!)
        renderProceduralDots(ctx, width, height);
      }

      // Technical Overlays (Clean Orbital Reticle Ring & Data Panels - NO STAR)
      if (showOverlays) {
        // 1. Orbital Reticle Ring (Crisp Champagne Gold & Ivory)
        ctx.save();
        const centerX = width * 0.50;
        const centerY = height * 0.44;
        const radius = Math.min(width, height) * 0.36;

        ctx.strokeStyle = 'rgba(243, 208, 129, 0.22)';
        ctx.lineWidth = 1;
        ctx.setLineDash([6, 8]);
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
        ctx.stroke();

        // Outer rotating technical ticks
        ctx.strokeStyle = 'rgba(243, 208, 129, 0.36)';
        ctx.setLineDash([14, 60]);
        ctx.beginPath();
        ctx.arc(
          centerX,
          centerY,
          radius + 14,
          rotationAngle,
          rotationAngle + Math.PI * 2
        );
        ctx.stroke();

        // Coordinate crosshair ticks at circle quadrants
        ctx.setLineDash([]);
        ctx.lineWidth = 1.5;
        const tickLen = 8;
        // North
        ctx.beginPath();
        ctx.moveTo(centerX, centerY - radius - tickLen);
        ctx.lineTo(centerX, centerY - radius + tickLen);
        ctx.stroke();
        // South
        ctx.beginPath();
        ctx.moveTo(centerX, centerY + radius - tickLen);
        ctx.lineTo(centerX, centerY + radius + tickLen);
        ctx.stroke();
        // East
        ctx.beginPath();
        ctx.moveTo(centerX + radius - tickLen, centerY);
        ctx.lineTo(centerX + radius + tickLen, centerY);
        ctx.stroke();
        // West
        ctx.beginPath();
        ctx.moveTo(centerX - radius - tickLen, centerY);
        ctx.lineTo(centerX - radius + tickLen, centerY);
        ctx.stroke();
        ctx.restore();

        // 2. Ambient Monospace Data Overlays (Hex dump and oscilloscope wave, NO STAR)
        renderTechnicalDataPanels(ctx, width, height, waveformPhase);
      }
    };

    // Procedural Dot-Matrix Halftone Fallback
    // Renders clean circular points on scanlines, NOT text characters!
    const renderProceduralDots = (
      c: CanvasRenderingContext2D,
      w: number,
      h: number
    ) => {
      c.save();
      c.fillStyle = '#FFFFFF';

      const leftStartX = -40;
      const leftEndX = w * 0.485;
      const leftY = h * 0.35; // Higher (God reaches from above)

      for (let x = leftStartX; x < leftEndX; x += 8) {
        const norm = (x - leftStartX) / (leftEndX - leftStartX);
        const yOffset = Math.sin(norm * Math.PI) * 45 * (1 - norm * 0.4);
        for (let dy = -yOffset; dy <= yOffset; dy += 8) {
          c.beginPath();
          c.arc(x, leftY + dy, 1.4, 0, Math.PI * 2);
          c.fill();
        }
      }

      const rightStartX = w * 0.515;
      const rightEndX = w + 40;
      const rightY = h * 0.50; // Lower (Adam reaches from below)

      for (let x = rightStartX; x < rightEndX; x += 8) {
        const norm = (x - rightStartX) / (rightEndX - rightStartX);
        const yOffset = Math.sin(norm * Math.PI) * 50 * norm;
        for (let dy = -yOffset; dy <= yOffset; dy += 8) {
          c.beginPath();
          c.arc(x, rightY + dy, 1.4, 0, Math.PI * 2);
          c.fill();
        }
      }
      c.restore();
    };

    // Technical Data Panels (Hex dump telemetry, file list, frequency wave)
    const renderTechnicalDataPanels = (
      c: CanvasRenderingContext2D,
      w: number,
      h: number,
      wavePhase: number
    ) => {
      if (w < 768) return;

      c.save();
      c.font = '10px "IBM Plex Mono", monospace';
      c.textBaseline = 'top';

      // Left Hex Dump Telemetry
      const hexLeft = Math.max(28, w * 0.035);
      const hexTop = h * 0.66;
      c.fillStyle = 'rgba(183, 196, 184, 0.65)'; // Muted Sage

      const hexRows = [
        '0000  54 72 75 73 74 53 68 69  65 6C 64 20 50 4B 49 20  TrustShield PKI',
        '0010  30 32 20 46 61 73 74 50  61 74 68 20 30 78 43 45  02 FastPath 0xCE',
        '0020  43 72 79 70 74 6F 20 45  6E 74 72 6F 70 79 20 4F  Crypto Entropy O',
        '0030  4A 41 34 53 20 41 69 54  4D 20 53 69 67 6E 61 6C  JA4S AiTM Signal',
        '0040  53 54 49 58 20 32 2E 31  20 54 41 58 49 49 20 43  STIX 2.1 TAXII C',
      ];

      hexRows.forEach((row, i) => {
        c.fillText(row, hexLeft, hexTop + i * 14);
      });

      // Target Corner Crosshair Bracket
      c.strokeStyle = GOLD_HEX;
      c.lineWidth = 1;
      const bX = hexLeft + 190;
      const bY = hexTop + 14;
      c.beginPath();
      c.moveTo(bX, bY - 8);
      c.lineTo(bX, bY - 14);
      c.lineTo(bX + 8, bY - 14);
      c.moveTo(bX + 22, bY - 14);
      c.lineTo(bX + 30, bY - 14);
      c.lineTo(bX + 30, bY - 8);
      c.stroke();

      // Right Oscilloscope Waveform Cluster
      const waveRight = w - 40;
      const waveLeft = Math.max(w * 0.72, w - 280);
      const waveTop = h * 0.72;
      const waveH = 48;

      c.strokeStyle = 'rgba(243, 208, 129, 0.48)';
      c.lineWidth = 1.2;
      c.beginPath();

      for (let x = waveLeft; x <= waveRight; x += 3) {
        const norm = (x - waveLeft) / (waveRight - waveLeft);
        const y =
          waveTop +
          waveH / 2 +
          Math.sin(norm * 14 + wavePhase) * 16 * Math.cos(norm * 5) +
          Math.sin(norm * 28 - wavePhase * 1.5) * 6;

        if (x === waveLeft) c.moveTo(x, y);
        else c.lineTo(x, y);
      }
      c.stroke();

      // Waveform scatter particles in Champagne Gold
      c.fillStyle = GOLD_HEX;
      for (let i = 0; i < 22; i++) {
        const norm = i / 22;
        const px = waveLeft + norm * (waveRight - waveLeft);
        const py =
          waveTop +
          waveH / 2 +
          Math.sin(norm * 14 + wavePhase) * 16 * Math.cos(norm * 5);
        c.fillRect(px, py, 1.8, 1.8);
      }

      c.restore();
    };

    // Animation Loop
    const loop = (timestamp: number) => {
      if (!isVisible) {
        animationFrameId = requestAnimationFrame(loop);
        return;
      }

      const elapsed = timestamp - lastRenderTime;

      if (elapsed >= FRAME_INTERVAL) {
        lastRenderTime = timestamp - (elapsed % FRAME_INTERVAL);

        if (!prefersReducedMotion) {
          rotationAngle += 0.0018;
          waveformPhase += 0.04;
        }

        renderFrame(timestamp);
      }

      if (!prefersReducedMotion) {
        animationFrameId = requestAnimationFrame(loop);
      }
    };

    if (prefersReducedMotion) {
      renderFrame(0);
    } else {
      animationFrameId = requestAnimationFrame(loop);
    }

    return () => {
      cancelAnimationFrame(animationFrameId);
      resizeObserver.disconnect();
      intersectionObserver.disconnect();
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseleave', handleMouseLeave);
    };
  }, [imageLoaded, accentColor, showOverlays, enableInteractiveGlow]);

  return (
    <div
      ref={containerRef}
      aria-hidden="true"
      className={`pointer-events-none select-none overflow-hidden ${className}`}
      style={{ opacity }}
    >
      <canvas ref={canvasRef} className="w-full h-full block" />
    </div>
  );
};
