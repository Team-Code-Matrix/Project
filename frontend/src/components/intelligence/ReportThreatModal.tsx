import React, { useState } from 'react';
import type { ThreatCategory } from '../../types/threatIntel';
import { validateAndNormalizeUrl } from '../../utils/urlValidator';
import { submitCommunityThreatReport } from '../../services/threatIntelService';
import { X, ShieldAlert, CheckCircle2, Lock, AlertCircle, Send } from 'lucide-react';

interface ReportThreatModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialUrl?: string;
}

export const ReportThreatModal: React.FC<ReportThreatModalProps> = ({
  isOpen,
  onClose,
  initialUrl = '',
}) => {
  const [url, setUrl] = useState(initialUrl);
  const [category, setCategory] = useState<ThreatCategory>('phishing');
  const [targetBrand, setTargetBrand] = useState('');
  const [notes, setNotes] = useState('');
  const [hasInteracted, setHasInteracted] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submittedTicket, setSubmittedTicket] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    const validation = validateAndNormalizeUrl(url);
    if (!validation.valid) {
      setErrorMsg(validation.message);
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await submitCommunityThreatReport({
        url: validation.normalizedUrl,
        category,
        targetBrand: targetBrand.trim() || undefined,
        notes: notes.trim() || undefined,
        hasInteracted,
      });
      setSubmittedTicket(res.reportId);
    } catch {
      setErrorMsg('Failed to transmit threat report. Please verify connection.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleResetAndClose = () => {
    setSubmittedTicket(null);
    setUrl('');
    setNotes('');
    setTargetBrand('');
    setHasInteracted(false);
    setErrorMsg(null);
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn"
      role="dialog"
      aria-modal="true"
      aria-labelledby="report-modal-title"
    >
      <div className="glass-panel-elevated rounded-3xl p-6 md:p-8 max-w-xl w-full border border-shield-border shadow-2xl relative max-h-[90vh] overflow-y-auto text-left">
        {/* Close Button */}
        <button
          type="button"
          onClick={handleResetAndClose}
          className="absolute top-6 right-6 p-2 rounded-xl text-shield-text-muted hover:text-shield-text-primary hover:bg-shield-surface transition-colors cursor-pointer"
        >
          <X className="w-5 h-5" />
        </button>

        {submittedTicket ? (
          /* Confirmation Screen */
          <div className="text-center py-6 space-y-4">
            <div className="w-16 h-16 rounded-full bg-shield-success/20 border border-shield-success/40 text-shield-success flex items-center justify-center mx-auto">
              <CheckCircle2 className="w-8 h-8" />
            </div>

            <h3 className="text-xl md:text-2xl font-bold text-shield-text-primary">
              Threat Report Received
            </h3>

            <p className="text-xs md:text-sm text-shield-text-secondary max-w-md mx-auto leading-relaxed">
              Thank you for contributing to collaborative cyber intelligence. Our automated sandboxes will correlate this target with threat feeds.
            </p>

            <div className="p-4 rounded-xl bg-shield-surface border border-shield-border inline-block font-mono text-xs text-shield-text-secondary">
              Submission Reference: <span className="text-shield-accent-light font-bold">{submittedTicket}</span>
            </div>

            <div className="pt-4">
              <button
                type="button"
                onClick={handleResetAndClose}
                className="clay-button px-6 py-2.5 rounded-xl text-xs md:text-sm font-bold text-white cursor-pointer"
              >
                Close Window
              </button>
            </div>
          </div>
        ) : (
          /* Submission Form */
          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-shield-danger/15 border border-shield-danger/30 text-shield-danger">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <div>
                <h3 id="report-modal-title" className="text-xl font-bold text-shield-text-primary">
                  Report a Suspicious Website
                </h3>
                <p className="text-xs text-shield-text-secondary">
                  Flag malicious links to protect everyday internet users
                </p>
              </div>
            </div>

            {errorMsg && (
              <div className="p-3 rounded-xl bg-shield-danger/15 border border-shield-danger/30 text-xs text-rose-300 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{errorMsg}</span>
              </div>
            )}

            {/* URL Input */}
            <div>
              <label className="block text-xs font-mono text-shield-text-secondary mb-1.5">
                Suspicious URL or Domain <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                required
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://deceptive-login-portal.com/auth"
                className="w-full px-3.5 py-2.5 rounded-xl clay-input text-xs font-mono text-shield-text-primary placeholder:text-shield-text-muted/60 outline-none"
              />
            </div>

            {/* Threat Category */}
            <div>
              <label className="block text-xs font-mono text-shield-text-secondary mb-1.5">
                Threat Classification
              </label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value as ThreatCategory)}
                className="w-full px-3.5 py-2.5 rounded-xl bg-[#080B09]/70 backdrop-blur-[3px] border border-[rgba(120,135,124,0.3)] text-xs font-mono text-shield-text-primary outline-none cursor-pointer focus:border-[#F3D081]/70"
              >
                <option value="phishing">Phishing Portal (Login Clone)</option>
                <option value="impersonation">Brand Impersonation / Typosquatting</option>
                <option value="credential_harvesting">Credential Harvesting Form</option>
                <option value="crypto_drainer">Crypto Wallet Drainer / Seed Thief</option>
                <option value="malware_distribution">Malware Dropper / Suspicious Executable</option>
                <option value="scam">Delivery / Fee / Invoice Scam</option>
                <option value="suspicious_redirect">Opaque Redirection Loop</option>
              </select>
            </div>

            {/* Target Brand (Optional) */}
            <div>
              <label className="block text-xs font-mono text-shield-text-secondary mb-1.5">
                Targeted Brand or Organization (Optional)
              </label>
              <input
                type="text"
                value={targetBrand}
                onChange={(e) => setTargetBrand(e.target.value)}
                placeholder="e.g. Microsoft, PayPal, Chase Bank, Apple"
                className="w-full px-3.5 py-2.5 rounded-xl clay-input text-xs font-mono text-shield-text-primary placeholder:text-shield-text-muted/60 outline-none"
              />
            </div>

            {/* Context Notes */}
            <div>
              <label className="block text-xs font-mono text-shield-text-secondary mb-1.5">
                Contextual Observations (Optional)
              </label>
              <textarea
                rows={3}
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Received via SMS asking for package delivery fee; prompted for credit card..."
                className="w-full px-3.5 py-2.5 rounded-xl clay-input text-xs font-mono text-shield-text-primary placeholder:text-shield-text-muted/60 outline-none resize-none"
              />
            </div>

            {/* Interaction Checkbox */}
            <label className="flex items-start gap-2.5 cursor-pointer text-xs text-shield-text-secondary">
              <input
                type="checkbox"
                checked={hasInteracted}
                onChange={(e) => setHasInteracted(e.target.checked)}
                className="mt-0.5 rounded border-shield-border bg-shield-surface text-shield-accent focus:ring-0"
              />
              <span>I inadvertently entered credentials or clicked buttons on this page.</span>
            </label>

            {/* Privacy & Anti-Dox Notice */}
            <div className="p-3.5 rounded-xl bg-shield-surface border border-shield-border/60 flex items-start gap-2.5 text-[11px] text-shield-text-muted">
              <Lock className="w-4 h-4 text-shield-accent-light shrink-0 mt-0.5" />
              <span>
                <strong>Privacy Protected:</strong> Reports are anonymised. Your IP address or identity is never stored or published. Community telemetry undergoes automated multi-source verification.
              </span>
            </div>

            {/* Submit Action */}
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={handleResetAndClose}
                className="px-4 py-2 rounded-xl text-xs font-mono text-shield-text-secondary hover:text-shield-text-primary transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting || !url.trim()}
                className="clay-button px-5 py-2.5 rounded-xl text-xs md:text-sm font-bold text-white flex items-center gap-2 disabled:opacity-50 cursor-pointer"
              >
                <Send className="w-4 h-4" />
                <span>{isSubmitting ? 'Transmitting...' : 'Submit Threat Report'}</span>
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
