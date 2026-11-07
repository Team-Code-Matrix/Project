import React from 'react';
import { X, ShieldAlert, Cpu, Award, AlertTriangle, Lock } from 'lucide-react';

interface MethodologyModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const MethodologyModal: React.FC<MethodologyModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn"
      role="dialog"
      aria-modal="true"
      aria-labelledby="methodology-title"
    >
      <div className="glass-panel-elevated rounded-3xl p-6 md:p-8 max-w-2xl w-full border border-shield-border shadow-2xl max-h-[90vh] overflow-y-auto space-y-6 text-left">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-shield-border/60">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-shield-accent/20 border border-shield-accent/30 text-shield-accent-light">
              <Award className="w-5 h-5" />
            </div>
            <div>
              <h3 id="methodology-title" className="text-xl font-bold text-shield-text-primary">
                Trust Score Methodology
              </h3>
              <p className="text-xs text-shield-text-muted font-mono">
                Explainable Multi-Signal Assessment Architecture
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-2 rounded-xl text-shield-text-muted hover:text-shield-text-primary hover:bg-shield-surface transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="space-y-5 text-xs md:text-sm text-shield-text-secondary leading-relaxed">
          <div className="space-y-2">
            <h4 className="text-sm font-bold text-shield-text-primary flex items-center gap-2">
              <Cpu className="w-4 h-4 text-shield-accent-light" />
              1. Multi-Model Aggregation
            </h4>
            <p>
              The Trust Score is an integer from 0 to 100 derived from six specialized intelligence models. Each model checks a different security dimension: Phishing Detection, Domain & Lexical structure, TLS certificate validity, Redirect hops, Web security headers, and Collaborative threat intelligence feeds.
            </p>
          </div>

          <div className="space-y-2">
            <h4 className="text-sm font-bold text-shield-text-primary flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-shield-danger" />
              2. Critical Malicious Overrides
            </h4>
            <p>
              A numeric score must never mask active malicious activity. If a model confirms severe indicators—such as active brand credential harvesting, unauthenticated credential exfiltration endpoints, or confirmed threat feed blacklists—the platform enforces a <strong>Critical Override</strong> regardless of whether other checks passed.
            </p>
          </div>

          <div className="space-y-2">
            <h4 className="text-sm font-bold text-shield-text-primary flex items-center gap-2">
              <Lock className="w-4 h-4 text-shield-warning" />
              3. The HTTPS Padlock Myth
            </h4>
            <p>
              A padlock icon in your browser only indicates that data between your browser and the server is encrypted using TLS. It does <em>not</em> prove that the server operator is legitimate. Attackers routinely obtain free automated TLS certificates for fraudulent domains. Trust Shield verifies the Certificate Authority and flags deceptive setups.
            </p>
          </div>

          <div className="space-y-2">
            <h4 className="text-sm font-bold text-shield-text-primary flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-shield-accent-light" />
              4. Honest Uncertainty & Skipped Checks
            </h4>
            <p>
              Missing or inconclusive telemetry is never treated as a "pass". When data is unavailable or a check times out, the model registers as "Unknown" or "Skipped", preventing artificially elevated scores.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-shield-surface border border-shield-border font-mono text-xs space-y-1 text-shield-text-muted">
            <div className="text-shield-text-primary font-bold">Standard Risk Bands:</div>
            <div>• 80 – 100: Lower Observed Risk (No major warnings observed)</div>
            <div>• 60 – 79: Caution (Anomalies or missing posture observed)</div>
            <div>• 30 – 59: High Risk (Multiple concerning flags)</div>
            <div>• 0 – 29: Critical Risk (Strong indicators of deception or exploit)</div>
          </div>
        </div>

        {/* Footer */}
        <div className="pt-4 border-t border-shield-border/60 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="clay-button px-5 py-2.5 rounded-xl text-xs md:text-sm font-bold text-white cursor-pointer"
          >
            Understood
          </button>
        </div>
      </div>
    </div>
  );
};
