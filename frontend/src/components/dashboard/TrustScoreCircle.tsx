import React, { useEffect, useState } from 'react';
import type { RiskLevel } from '../../types/scan';
import { getRiskColorClass } from '../../utils/formatters';
import { RiskBadge } from '../shared/RiskBadge';
import { ShieldAlert } from 'lucide-react';

interface TrustScoreCircleProps {
  score: number | null;
  riskLevel: RiskLevel;
  criticalOverride?: boolean;
  overrideReason?: string;
  size?: number;
}

export const TrustScoreCircle: React.FC<TrustScoreCircleProps> = ({
  score,
  riskLevel,
  criticalOverride = false,
  overrideReason,
  size = 280,
}) => {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    if (score === null) return;
    const duration = 1200; // ms
    const startTime = performance.now();

    const animate = (currentTime: number) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const easeOut = 1 - (1 - progress) * (1 - progress);
      setAnimatedScore(Math.round(easeOut * score));

      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };

    requestAnimationFrame(animate);
  }, [score]);

  const radius = (size - 36) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokePercent = score !== null ? (animatedScore / 100) * circumference : 0;
  const strokeDashoffset = circumference - strokePercent;

  const colorStyles = getRiskColorClass(riskLevel);

  return (
    <div className="flex flex-col items-center justify-center p-6 md:p-8">
      {/* Critical Override Banner if Malicious Indicator Confirmed */}
      {criticalOverride && (
        <div className="w-full mb-6 p-4 rounded-2xl bg-shield-danger/15 border border-shield-danger/40 text-rose-300 text-xs md:text-sm flex items-start gap-3.5 shadow-clay-card animate-fadeIn">
          <ShieldAlert className="w-5 h-5 text-shield-danger shrink-0 mt-0.5" />
          <div className="text-left">
            <div className="font-bold text-shield-danger uppercase tracking-wider mb-0.5 flex items-center gap-2">
              <span>Security Threat Override Active</span>
              <span className="text-[10px] bg-shield-danger/25 px-2 py-0.5 rounded font-mono">
                CRITICAL WARNING
              </span>
            </div>
            <p className="text-shield-text-primary text-xs md:text-sm leading-relaxed">
              {overrideReason ||
                'A confirmed malicious indicator takes precedence over the numerical score. Do not interact with or provide credentials to this destination.'}
            </p>
          </div>
        </div>
      )}

      {/* Radial Score Gauge */}
      <div
        className="relative flex items-center justify-center select-none"
        style={{ width: size, height: size }}
      >
        <svg
          className="transform -rotate-90"
          width={size}
          height={size}
          viewBox={`0 0 ${size} ${size}`}
        >
          {/* Subtle track shadow ring */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="#101713"
            strokeWidth="16"
          />

          {/* Background Track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="rgba(190, 215, 198, 0.08)"
            strokeWidth="12"
            strokeLinecap="round"
          />

          {/* Animated Value Arc */}
          {score !== null && (
            <circle
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="none"
              stroke={colorStyles.stroke}
              strokeWidth="12"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              className="transition-all duration-300 ease-out"
            />
          )}
        </svg>

        {/* Center Content */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="text-xs font-mono tracking-widest text-shield-text-muted uppercase mb-1">
            TRUST SCORE
          </span>

          {score !== null ? (
            <div className="flex items-baseline justify-center">
              <span className="text-6xl md:text-7xl font-black tracking-tighter text-[#E9E6DC] tabular-nums font-sans">
                {animatedScore}
              </span>
              <span className="text-lg md:text-xl font-mono text-[#78877C] ml-1">
                / 100
              </span>
            </div>
          ) : (
            <span className="text-2xl font-bold text-[#B7C4B8] font-mono">
              N/A
            </span>
          )}

          <div className="mt-3">
            <RiskBadge level={riskLevel} size="sm" />
          </div>
        </div>
      </div>

      <div className="mt-4 text-center">
        <p className="text-xs text-shield-text-muted font-mono">
          Correlated verdict from 6 autonomous security models
        </p>
      </div>
    </div>
  );
};
