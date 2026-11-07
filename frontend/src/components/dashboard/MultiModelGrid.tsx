import React from 'react';
import type { ModelResult } from '../../types/scan';
import { ModelCard } from './ModelCard';
import { Cpu } from 'lucide-react';

interface MultiModelGridProps {
  models: ModelResult[];
}

export const MultiModelGrid: React.FC<MultiModelGridProps> = ({ models }) => {
  return (
    <div className="space-y-6 text-left">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-shield-accent/20 border border-shield-accent/30 text-shield-accent-light">
            <Cpu className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-xl md:text-2xl font-bold text-shield-text-primary">
              Multi-Model Analysis Verdicts
            </h2>
            <p className="text-xs text-shield-text-secondary">
              Individual model assessments evaluated in isolation before correlation
            </p>
          </div>
        </div>

        <div className="text-xs font-mono text-shield-text-muted">
          <span>6 of 6 Models Evaluated</span>
        </div>
      </div>

      {/* Grid of 6 Models */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {models.map((model) => (
          <ModelCard key={model.id} model={model} />
        ))}
      </div>
    </div>
  );
};
