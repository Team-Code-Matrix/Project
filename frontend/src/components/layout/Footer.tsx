import React from 'react';
import { Shield, Lock } from 'lucide-react';

interface FooterProps {
  onOpenMethodology: () => void;
  onOpenReportModal: () => void;
}

const CURRENT_YEAR = new Date().getFullYear();

export const Footer: React.FC<FooterProps> = ({
  onOpenMethodology,
  onOpenReportModal,
}) => {
  return (
    <footer id="about" className="w-full border-t border-shield-border/70 bg-[#080D0B] py-14 px-4 text-left">
      <div className="max-w-7xl mx-auto space-y-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Brand Info */}
          <div className="space-y-4 md:col-span-2">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-shield-surface border border-shield-border">
                <Shield className="w-5 h-5 text-shield-accent-light" />
              </div>
              <span className="text-lg font-bold font-mono tracking-tight text-shield-text-primary">
                TRUST SHIELD
              </span>
            </div>

            <p className="text-xs md:text-sm text-shield-text-secondary max-w-md leading-relaxed">
              An intelligent website trust assessment platform combining multi-model analysis across phishing detection, domain reputation, TLS certificate validation, redirect tracking, and collaborative threat intelligence.
            </p>

            <div className="text-xs font-mono text-shield-text-muted">
              Built with precision for everyday internet safety.
            </div>
          </div>

          {/* Product & Engine Links */}
          <div className="space-y-3">
            <h4 className="text-xs font-mono uppercase tracking-wider text-shield-text-primary">
              Architecture & Engine
            </h4>
            <ul className="space-y-2 text-xs font-mono text-shield-text-secondary">
              <li>
                <button
                  type="button"
                  onClick={onOpenMethodology}
                  className="hover:text-shield-accent-light transition-colors text-left cursor-pointer"
                >
                  Score Methodology
                </button>
              </li>
              <li>
                <a href="#features" className="hover:text-shield-accent-light transition-colors">
                  Six Analysis Pillars
                </a>
              </li>
              <li>
                <a href="#how-it-works" className="hover:text-shield-accent-light transition-colors">
                  Verification Pipeline
                </a>
              </li>
              <li>
                <button
                  type="button"
                  onClick={onOpenReportModal}
                  className="hover:text-shield-accent-light transition-colors text-left cursor-pointer"
                >
                  Submit Threat Report
                </button>
              </li>
            </ul>
          </div>

          {/* Integrity & Disclosures */}
          <div className="space-y-3">
            <h4 className="text-xs font-mono uppercase tracking-wider text-shield-text-primary">
              Safety Principles
            </h4>
            <div className="text-xs text-shield-text-secondary leading-relaxed space-y-2">
              <p>
                <strong>No Arbitrary Browser Fetch:</strong> Client JavaScript never contacts submitted target URLs directly. All analysis is proxied and sandboxed.
              </p>
              <p>
                <strong>Indicator, Not Guarantee:</strong> Security is continuous. A score reflects observed signals in performed checks.
              </p>
            </div>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="pt-8 border-t border-shield-border/40 flex flex-col sm:flex-row items-center justify-between text-xs font-mono text-shield-text-muted gap-4">
          <div>
            © {CURRENT_YEAR} Trust Shield Intelligence. Frontend Implementation Prototype.
          </div>
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-shield-accent-light" />
              WCAG 2.2 AA Conforming
            </span>
            <span className="w-1.5 h-1.5 rounded-full bg-shield-border" />
            <span>Futuristic Minimalism Design System</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
