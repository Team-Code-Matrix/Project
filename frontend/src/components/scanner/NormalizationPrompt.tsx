import React from 'react';
import { Check, Sparkles } from 'lucide-react';

interface NormalizationPromptProps {
  originalInput: string;
  normalizedUrl: string;
  onConfirm: () => void;
  onDismiss: () => void;
}

export const NormalizationPrompt: React.FC<NormalizationPromptProps> = ({
  originalInput,
  normalizedUrl,
  onConfirm,
  onDismiss,
}) => {
  return (
    <div className="mt-3 p-3.5 rounded-xl bg-shield-surface-elevated border border-shield-accent/30 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3 animate-fadeIn">
      <div className="flex items-center gap-2.5">
        <div className="p-1.5 rounded-lg bg-shield-accent/20 text-shield-accent-light shrink-0">
          <Sparkles className="w-4 h-4" />
        </div>
        <div>
          <span className="text-shield-text-secondary">
            Bare domain <span className="font-mono text-shield-text-primary">"{originalInput}"</span> normalized to secure scheme:
          </span>{' '}
          <code className="text-shield-accent-light font-mono font-semibold">{normalizedUrl}</code>
        </div>
      </div>

      <div className="flex items-center gap-2 shrink-0">
        <button
          type="button"
          onClick={onConfirm}
          className="clay-button px-3.5 py-1.5 rounded-lg text-xs font-semibold text-white inline-flex items-center gap-1.5 cursor-pointer"
        >
          <Check className="w-3.5 h-3.5" />
          <span>Use HTTPS</span>
        </button>
        <button
          type="button"
          onClick={onDismiss}
          className="px-2.5 py-1.5 rounded-lg text-xs text-shield-text-secondary hover:text-shield-text-primary transition-colors cursor-pointer"
        >
          Keep original
        </button>
      </div>
    </div>
  );
};
