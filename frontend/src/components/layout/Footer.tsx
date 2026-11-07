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
    <footer id="about" className="w-full border-t border-[rgba(120,135,124,0.25)] bg-[#080B09] py-14 px-4 text-left">
      <div className="max-w-7xl mx-auto space-y-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Brand Info */}
          <div className="space-y-4 md:col-span-2">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-[#101713] border border-[rgba(120,135,124,0.3)]">
                <Shield className="w-5 h-5 text-[#F3D081]" />
              </div>
              <span className="text-lg font-black font-sans tracking-tight uppercase text-[#E9E6DC]">
                TRUST SHIELD
              </span>
            </div>

            <p className="text-xs md:text-sm text-[#B7C4B8] max-w-md leading-relaxed">
              An intelligent website trust assessment platform combining multi-model analysis across phishing detection, domain reputation, TLS certificate validation, redirect tracking, and collaborative threat intelligence.
            </p>

            <div className="text-xs font-mono text-[#78877C] uppercase tracking-wider">
              SYS_SPEC: BUILT FOR HIGH-ASSURANCE INTERNET SAFETY.
            </div>
          </div>

          {/* Product & Engine Links */}
          <div className="space-y-3">
            <h4 className="text-xs font-mono uppercase tracking-wider text-[#E9E6DC] font-bold">
              Architecture & Engine
            </h4>
            <ul className="space-y-2 text-xs font-mono text-[#B7C4B8]">
              <li>
                <button
                  type="button"
                  onClick={onOpenMethodology}
                  className="hover:text-[#F3D081] transition-colors text-left cursor-pointer"
                >
                  Score Methodology
                </button>
              </li>
              <li>
                <a href="#features" className="hover:text-[#F3D081] transition-colors">
                  Six Analysis Pillars
                </a>
              </li>
              <li>
                <a href="#how-it-works" className="hover:text-[#F3D081] transition-colors">
                  Verification Pipeline
                </a>
              </li>
              <li>
                <button
                  type="button"
                  onClick={onOpenReportModal}
                  className="hover:text-[#F3D081] transition-colors text-left cursor-pointer"
                >
                  Submit Threat Report
                </button>
              </li>
            </ul>
          </div>

          {/* Integrity & Disclosures */}
          <div className="space-y-3">
            <h4 className="text-xs font-mono uppercase tracking-wider text-[#E9E6DC] font-bold">
              Safety Principles
            </h4>
            <div className="text-xs text-[#B7C4B8] leading-relaxed space-y-2">
              <p>
                <strong className="text-[#E9E6DC]">Zero Arbitrary Client Fetch:</strong> Client JavaScript never contacts submitted target URLs directly. All analysis is proxied and sandboxed.
              </p>
              <p>
                <strong className="text-[#E9E6DC]">Indicator, Not Guarantee:</strong> Security is continuous. A score reflects observed signals in performed checks.
              </p>
            </div>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="pt-8 border-t border-[rgba(120,135,124,0.25)] flex flex-col sm:flex-row items-center justify-between text-xs font-mono text-[#78877C] gap-4">
          <div>
            © {CURRENT_YEAR} TRUST SHIELD INTELLIGENCE. ALL RIGHTS RESERVED.
          </div>
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1.5 text-[#F3D081]">
              <Lock className="w-3.5 h-3.5 text-[#F3D081]" />
              RFC-3986 & WCAG 2.2 AA
            </span>
            <span className="w-1.5 h-1.5 rounded-full bg-[rgba(120,135,124,0.4)]" />
            <span>SWISS INTERNATIONAL BRUTALIST ARCHITECTURE</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
