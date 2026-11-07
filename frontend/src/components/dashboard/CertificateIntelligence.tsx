import React, { useState } from 'react';
import type { PkiIntelligence, CertificateSummaryItem } from '../../types/backend';
import {
  Lock,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Cpu,
  Layers,
  FileCheck2,
  Radio,
  ExternalLink,
  KeyRound,
  Network,
} from 'lucide-react';

interface CertificateIntelligenceProps {
  pki: PkiIntelligence;
  isPkiCompromised?: boolean;
}

export const CertificateIntelligence: React.FC<CertificateIntelligenceProps> = ({
  pki,
  isPkiCompromised = false,
}) => {
  const [activeTab, setActiveTab] = useState<'chain' | 'crypto' | 'ct' | 'revocation' | 'caa'>('chain');
  const [selectedCertIndex, setSelectedCertIndex] = useState<number>(0);
  const [copiedFingerprint, setCopiedFingerprint] = useState(false);
  const [copiedPem, setCopiedPem] = useState(false);

  const selectedCert = pki.chain[selectedCertIndex] || pki.chain[0];

  const handleCopyFingerprint = async () => {
    if (!selectedCert) return;
    try {
      await navigator.clipboard.writeText(selectedCert.sha256Fingerprint);
      setCopiedFingerprint(true);
      setTimeout(() => setCopiedFingerprint(false), 2000);
    } catch {
      // Fallback
    }
  };

  const handleCopyPem = async () => {
    if (!selectedCert?.rawPem) return;
    try {
      await navigator.clipboard.writeText(selectedCert.rawPem);
      setCopiedPem(true);
      setTimeout(() => setCopiedPem(false), 2000);
    } catch {
      // Fallback
    }
  };

  return (
    <div className="clay-card rounded-3xl p-6 md:p-8 space-y-6 text-left border border-shield-border/80">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-shield-border/60">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-shield-accent/20 border border-shield-accent/30 text-shield-accent-light">
            <Lock className="w-5 h-5 text-shield-accent-light" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xl md:text-2xl font-bold text-shield-text-primary">
                Cryptographic PKI & Certificate Intelligence
              </h2>
              {isPkiCompromised && (
                <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-purple-950/60 text-purple-300 border border-purple-500/50 animate-pulse">
                  PKI ALERT
                </span>
              )}
            </div>
            <p className="text-xs text-shield-text-secondary mt-0.5">
              Multi-store path verification, key-entropy parameters, Certificate Transparency & CA revocation health
            </p>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex flex-wrap items-center gap-1.5 p-1 rounded-xl bg-shield-surface-elevated border border-shield-border text-xs font-mono">
          <button
            type="button"
            onClick={() => setActiveTab('chain')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
              activeTab === 'chain'
                ? 'bg-shield-accent text-white font-semibold'
                : 'text-shield-text-secondary hover:text-shield-text-primary'
            }`}
          >
            Cert Chain ({pki.chain.length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('crypto')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
              activeTab === 'crypto'
                ? 'bg-shield-accent text-white font-semibold'
                : 'text-shield-text-secondary hover:text-shield-text-primary'
            }`}
          >
            Key Entropy & Curve
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('ct')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
              activeTab === 'ct'
                ? 'bg-shield-accent text-white font-semibold'
                : 'text-shield-text-secondary hover:text-shield-text-primary'
            }`}
          >
            CT Logs & SCTs
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('revocation')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
              activeTab === 'revocation'
                ? 'bg-shield-accent text-white font-semibold'
                : 'text-shield-text-secondary hover:text-shield-text-primary'
            }`}
          >
            Revocation & OCSP
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('caa')}
            className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
              activeTab === 'caa'
                ? 'bg-shield-accent text-white font-semibold'
                : 'text-shield-text-secondary hover:text-shield-text-primary'
            }`}
          >
            DNS CAA Policy
          </button>
        </div>
      </div>

      {/* Compromise Warning Callout if key ceremony or intermediate failure is active */}
      {pki.keyCeremonyAnomalyFlag && (
        <div className="p-4 rounded-2xl bg-purple-950/25 border border-purple-500/40 text-purple-200 text-xs md:text-sm flex items-start gap-3.5 shadow-clay-card animate-fadeIn">
          <ShieldAlert className="w-5 h-5 text-purple-400 shrink-0 mt-0.5" />
          <div>
            <div className="font-bold uppercase tracking-wider mb-1 flex items-center gap-2">
              <span>Cryptographic CA Key Ceremony Anomaly Detected</span>
              <span className="text-[10px] bg-purple-950/60 px-2 py-0.5 rounded font-mono border border-purple-500/40">
                CRITICAL PKI FAILURE
              </span>
            </div>
            <p className="text-purple-300 leading-relaxed">
              {pki.keyCeremonyNotes ||
                'Intermediate CA certificate was issued under an unvetted key ceremony script with weak scalar entropy (<256) or invalid CRL signatures, undermining trust store legitimacy.'}
            </p>
          </div>
        </div>
      )}

      {/* TAB 1: CERTIFICATE CHAIN & MULTI-STORE VALIDATION */}
      {activeTab === 'chain' && (
        <div className="space-y-6 animate-fadeIn">
          {/* Certificate Hierarchy Visualizer */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {pki.chain.map((cert, idx) => {
              const isSelected = selectedCertIndex === idx;
              return (
                <div
                  key={cert.serialNumber}
                  onClick={() => setSelectedCertIndex(idx)}
                  className={`p-4 rounded-2xl border transition-all cursor-pointer flex flex-col justify-between ${
                    isSelected
                      ? 'bg-shield-surface-elevated border-shield-accent shadow-clay-card'
                      : 'bg-shield-surface/60 border-shield-border/70 hover:bg-shield-surface'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[11px] font-mono uppercase px-2 py-0.5 rounded bg-[#090F0C] border border-shield-border text-shield-accent-light">
                        {cert.type === 'leaf' ? 'Leaf Certificate' : cert.type === 'intermediate' ? `Intermediate [${idx}]` : 'Root CA'}
                      </span>
                      <span className={`text-[11px] font-mono ${cert.isExpired ? 'text-shield-danger' : 'text-shield-success'}`}>
                        {cert.isExpired ? 'EXPIRED' : `${cert.daysRemaining}d left`}
                      </span>
                    </div>

                    <h4 className="text-sm font-bold text-shield-text-primary truncate">
                      {cert.subjectCommonName}
                    </h4>
                    <p className="text-xs text-shield-text-muted truncate mt-0.5">
                      Issuer: {cert.issuerCommonName}
                    </p>
                  </div>

                  <div className="mt-4 pt-3 border-t border-shield-border/40 text-[11px] font-mono text-shield-text-secondary flex justify-between">
                    <span>{cert.publicKeyAlgorithm} {cert.keySizeBits}-bit</span>
                    <span className="text-shield-accent-light">Click to inspect</span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Selected Certificate Deep-Dive Inspector */}
          {selectedCert && (
            <div className="p-6 rounded-2xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.28)] hover:border-[#F3D081]/30 transition-all font-mono text-xs space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-shield-border/40 gap-2">
                <span className="text-shield-text-primary font-bold text-sm">
                  X.509 Certificate Parameter Inspector [{selectedCert.type.toUpperCase()}]
                </span>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleCopyFingerprint}
                    className="clay-button-secondary px-2.5 py-1 rounded-lg text-[11px] text-shield-text-secondary hover:text-white flex items-center gap-1.5 cursor-pointer"
                  >
                    {copiedFingerprint ? <Check className="w-3 h-3 text-shield-success" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedFingerprint ? 'Copied' : 'Copy Fingerprint'}</span>
                  </button>
                  {selectedCert.rawPem && (
                    <button
                      type="button"
                      onClick={handleCopyPem}
                      className="clay-button-secondary px-2.5 py-1 rounded-lg text-[11px] text-shield-text-secondary hover:text-white flex items-center gap-1.5 cursor-pointer"
                    >
                      {copiedPem ? <Check className="w-3 h-3 text-shield-success" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedPem ? 'Copied' : 'Copy PEM'}</span>
                    </button>
                  )}
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2 text-shield-text-secondary">
                <div>
                  <span className="text-shield-text-muted">Subject CN:</span>{' '}
                  <span className="text-shield-text-primary">{selectedCert.subjectCommonName}</span>
                </div>
                <div>
                  <span className="text-shield-text-muted">Subject Org:</span>{' '}
                  <span className="text-shield-text-primary">{selectedCert.subjectOrg || 'None (Domain Validation)'}</span>
                </div>
                <div>
                  <span className="text-shield-text-muted">Issuer CN:</span>{' '}
                  <span className="text-shield-text-primary">{selectedCert.issuerCommonName}</span>
                </div>
                <div>
                  <span className="text-shield-text-muted">Serial Number:</span>{' '}
                  <span className="text-shield-accent-light break-all">{selectedCert.serialNumber}</span>
                </div>
                <div>
                  <span className="text-shield-text-muted">Valid From:</span>{' '}
                  <span>{new Date(selectedCert.validFrom).toUTCString()}</span>
                </div>
                <div>
                  <span className="text-shield-text-muted">Valid Until:</span>{' '}
                  <span>{new Date(selectedCert.validUntil).toUTCString()}</span>
                </div>
                <div>
                  <span className="text-shield-text-muted">Signature Algorithm:</span>{' '}
                  <span className="text-shield-text-primary">{selectedCert.signatureAlgorithm}</span>
                </div>
                <div>
                  <span className="text-shield-text-muted">Key Specification:</span>{' '}
                  <span className="text-shield-text-primary">{selectedCert.publicKeyAlgorithm} ({selectedCert.keySizeBits} bits)</span>
                </div>
                <div className="md:col-span-2 pt-2 border-t border-shield-border/30">
                  <span className="text-shield-text-muted">SHA-256 Fingerprint:</span>{' '}
                  <span className="text-shield-accent-light break-all">{selectedCert.sha256Fingerprint}</span>
                </div>
              </div>

              {/* Multi-Store Trust Matrix */}
              <div className="pt-3 border-t border-shield-border/40">
                <div className="text-shield-text-muted text-[11px] uppercase tracking-wider mb-2.5">
                  Multi-Store RFC 5280 Trust Compatibility:
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-center text-[11px]">
                  <div className="p-2 rounded-lg bg-shield-surface border border-shield-border/50">
                    <div className="text-shield-text-muted mb-1">Mozilla NSS</div>
                    <span className={pki.trustStoreCompatibility.mozillaNss ? 'text-shield-success font-bold' : 'text-shield-danger font-bold'}>
                      {pki.trustStoreCompatibility.mozillaNss ? '✓ TRUSTED' : '✗ DISTRUSTED'}
                    </span>
                  </div>
                  <div className="p-2 rounded-lg bg-shield-surface border border-shield-border/50">
                    <div className="text-shield-text-muted mb-1">Chrome Root</div>
                    <span className={pki.trustStoreCompatibility.chromeRoot ? 'text-shield-success font-bold' : 'text-shield-danger font-bold'}>
                      {pki.trustStoreCompatibility.chromeRoot ? '✓ TRUSTED' : '✗ DISTRUSTED'}
                    </span>
                  </div>
                  <div className="p-2 rounded-lg bg-shield-surface border border-shield-border/50">
                    <div className="text-shield-text-muted mb-1">Apple macOS/iOS</div>
                    <span className={pki.trustStoreCompatibility.apple ? 'text-shield-success font-bold' : 'text-shield-danger font-bold'}>
                      {pki.trustStoreCompatibility.apple ? '✓ TRUSTED' : '✗ DISTRUSTED'}
                    </span>
                  </div>
                  <div className="p-2 rounded-lg bg-shield-surface border border-shield-border/50">
                    <div className="text-shield-text-muted mb-1">Microsoft</div>
                    <span className={pki.trustStoreCompatibility.microsoft ? 'text-shield-success font-bold' : 'text-shield-danger font-bold'}>
                      {pki.trustStoreCompatibility.microsoft ? '✓ TRUSTED' : '✗ DISTRUSTED'}
                    </span>
                  </div>
                  <div className="p-2 rounded-lg bg-shield-surface border border-shield-border/50">
                    <div className="text-shield-text-muted mb-1">Oracle Java</div>
                    <span className={pki.trustStoreCompatibility.oracleJava ? 'text-shield-success font-bold' : 'text-shield-danger font-bold'}>
                      {pki.trustStoreCompatibility.oracleJava ? '✓ TRUSTED' : '✗ DISTRUSTED'}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: KEY ENTROPY & CURVE PARAMETER AUDIT */}
      {activeTab === 'crypto' && (
        <div className="space-y-4 animate-fadeIn font-mono text-xs">
          <div className="p-4 rounded-2xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.28)] space-y-3">
            <div className="flex items-center justify-between border-b border-shield-border/40 pb-2">
              <span className="text-shield-text-primary font-bold text-sm">
                Cryptographic Key-Entropy & Curve Parameter Verification
              </span>
              <span className={`px-2.5 py-0.5 rounded text-xs font-bold ${
                pki.keyEntropyVerdict === 'VALID' ? 'bg-[#2A2111]/80 text-[#F3D081] border border-[#F3D081]/30' : 'bg-rose-950 text-rose-300'
              }`}>
                {pki.keyEntropyVerdict}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-shield-text-secondary pt-2">
              <div className="p-3 rounded-xl bg-shield-surface/60 border border-shield-border/50 flex flex-col justify-between">
                <div>
                  <div className="text-shield-text-primary font-semibold mb-1">Fermat Factorization Audit</div>
                  <p className="text-[11px] text-shield-text-muted">
                    Probes for close primes in RSA modulus generation (CVE-2022-26320).
                  </p>
                </div>
                <div className="mt-2 text-shield-success font-bold">
                  {pki.fermatFactorizationPassed ? '✓ Passed (No trivial factor)' : '✗ Vulnerable to factorization'}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-shield-surface/60 border border-shield-border/50 flex flex-col justify-between">
                <div>
                  <div className="text-shield-text-primary font-semibold mb-1">Small-Prime GCD Checks</div>
                  <p className="text-[11px] text-shield-text-muted">
                    Cross-computes greatest common divisors against global certificate moduli datasets.
                  </p>
                </div>
                <div className="mt-2 text-shield-success font-bold">
                  {pki.smallPrimeGcdPassed ? '✓ Passed (Distinct Prime Factors)' : '✗ Shared Prime Anomaly'}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-shield-surface/60 border border-shield-border/50 flex flex-col justify-between">
                <div>
                  <div className="text-shield-text-primary font-semibold mb-1">ECDSA Curve Subgroup Validation</div>
                  <p className="text-[11px] text-shield-text-muted">
                    Confirms public key points strictly lie on prime-order subgroup without scalar leakage.
                  </p>
                </div>
                <div className="mt-2 text-shield-success font-bold">
                  {pki.curvePointValid ? '✓ Valid Curve Point (Order = P-256/384)' : '✗ Small-Subgroup Weakness'}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-shield-surface/60 border border-shield-border/50 flex flex-col justify-between">
                <div>
                  <div className="text-shield-text-primary font-semibold mb-1">Cross-Signed Distrust Bypass Check</div>
                  <p className="text-[11px] text-shield-text-muted">
                    Detects distrusted CAs chaining through alternate cross-signed legacy roots (RFC 6818).
                  </p>
                </div>
                <div className={`mt-2 font-bold ${pki.crossSignedBypassDetected ? 'text-shield-danger' : 'text-shield-success'}`}>
                  {pki.crossSignedBypassDetected ? '⚠ Distrusted Cross-Sign Observed' : '✓ Clean Path Topology'}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: CERTIFICATE TRANSPARENCY & SCTS */}
      {activeTab === 'ct' && (
        <div className="space-y-4 animate-fadeIn font-mono text-xs">
          <div className="p-5 rounded-2xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.28)] space-y-4">
            <div className="flex items-center justify-between border-b border-shield-border/40 pb-2">
              <span className="text-shield-text-primary font-bold text-sm">
                Certificate Transparency (CT) Stream Verification (RFC 6962 / RFC 9162 CT v2.0)
              </span>
              <span className="px-2.5 py-0.5 rounded bg-[#2A2111]/80 text-[#F3D081] border border-[#F3D081]/30">
                {pki.certificateTransparency.sctsDeliveredCount} SCTs Delivered
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-shield-text-secondary">
              <div className="p-3 rounded-xl bg-shield-surface border border-shield-border/50">
                <div className="text-shield-text-muted mb-1">Merkle Inclusion Status</div>
                <div className="font-bold text-[#F3D081]">
                  {pki.certificateTransparency.merkleInclusionProofStatus}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-shield-surface border border-shield-border/50">
                <div className="text-shield-text-muted mb-1">Signed Tree Head (STH)</div>
                <div className="font-bold text-shield-text-primary truncate">
                  {pki.certificateTransparency.signedTreeHeadTimestamp}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-shield-surface border border-shield-border/50">
                <div className="text-shield-text-muted mb-1">Rogue Issuance Alert</div>
                <div className={`font-bold ${pki.certificateTransparency.unexpectedIssuanceAlert ? 'text-shield-danger' : 'text-[#F3D081]'}`}>
                  {pki.certificateTransparency.unexpectedIssuanceAlert ? 'ALERT: Unexpected CA' : 'Clean (Expected Authority)'}
                </div>
              </div>
            </div>

            <div className="pt-2 text-shield-text-muted text-[11px] leading-relaxed">
              Delivered Signed Certificate Timestamps (SCTs) via: {pki.certificateTransparency.sctSources.join(', ')}.
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: REVOCATION & CA HEALTH MONITOR */}
      {activeTab === 'revocation' && (
        <div className="space-y-4 animate-fadeIn font-mono text-xs">
          <div className="p-5 rounded-2xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.28)] space-y-4">
            <div className="flex items-center justify-between border-b border-shield-border/40 pb-2">
              <span className="text-shield-text-primary font-bold text-sm">
                Multi-Channel Revocation Telemetry & CA Health (RFC 6960 OCSP / CRL)
              </span>
              <span className={`px-2.5 py-0.5 rounded font-bold ${
                pki.revocationHealth.ocspStatus === 'GOOD' ? 'bg-[#2A2111]/80 text-[#F3D081] border border-[#F3D081]/30' : 'bg-rose-950 text-rose-300'
              }`}>
                OCSP: {pki.revocationHealth.ocspStatus}
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-shield-text-secondary">
              <div className="p-3 rounded-xl bg-shield-surface border border-shield-border/50">
                <div className="text-shield-text-muted mb-1">OCSP Stapling</div>
                <div className={`font-bold ${pki.revocationHealth.ocspStapled ? 'text-[#F3D081]' : 'text-shield-warning'}`}>
                  {pki.revocationHealth.ocspStapled ? 'Active (Stapled)' : 'Not Stapled'}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-shield-surface border border-shield-border/50">
                <div className="text-shield-text-muted mb-1">Must-Staple Flag</div>
                <div className="font-bold text-shield-text-primary">
                  {pki.revocationHealth.mustStapleCompliant ? 'Enforced' : 'Not Set'}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-shield-surface border border-shield-border/50">
                <div className="text-shield-text-muted mb-1">CRL Signature</div>
                <div className={`font-bold ${pki.revocationHealth.crlSignatureValid ? 'text-[#F3D081]' : 'text-shield-danger'}`}>
                  {pki.revocationHealth.crlSignatureValid ? 'Cryptographically Valid' : 'INVALID SIGNATURE'}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-shield-surface border border-shield-border/50">
                <div className="text-shield-text-muted mb-1">Mozilla OneCRL</div>
                <div className={`font-bold ${pki.revocationHealth.oneCrlIncluded ? 'text-shield-danger' : 'text-[#F3D081]'}`}>
                  {pki.revocationHealth.oneCrlIncluded ? 'REVOKED IN ONECRL' : 'Clean'}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: DNS CAA POLICY CHECKER */}
      {activeTab === 'caa' && (
        <div className="space-y-4 animate-fadeIn font-mono text-xs">
          <div className="p-5 rounded-2xl bg-[#080B09]/60 backdrop-blur-[3px] border border-[rgba(120,135,124,0.28)] space-y-4">
            <div className="flex items-center justify-between border-b border-shield-border/40 pb-2">
              <span className="text-shield-text-primary font-bold text-sm">
                Authoritative DNS Certification Authority Authorization (RFC 8659 CAA)
              </span>
              <span className={`px-2.5 py-0.5 rounded font-bold ${
                pki.dnsCaaPolicy.policyMismatch ? 'bg-rose-950 text-rose-300' : 'bg-[#2A2111]/80 text-[#F3D081] border border-[#F3D081]/30'
              }`}>
                {pki.dnsCaaPolicy.policyMismatch ? 'CAA POLICY MISMATCH' : 'CAA COMPLIANT'}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-shield-text-secondary">
              <div className="p-3 rounded-xl bg-shield-surface border border-shield-border/50">
                <div className="text-shield-text-muted mb-1">Authoritative Allowed Issuers (DNS):</div>
                <div className="font-bold text-shield-text-primary">
                  {pki.dnsCaaPolicy.allowedIssuers.length > 0
                    ? pki.dnsCaaPolicy.allowedIssuers.join(', ')
                    : 'No CAA records (Any valid CA permitted)'}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-shield-surface border border-shield-border/50">
                <div className="text-shield-text-muted mb-1">Actual Issuing Authority (X.509):</div>
                <div className="font-bold text-shield-accent-light">
                  {pki.dnsCaaPolicy.actualIssuer}
                </div>
              </div>
            </div>

            {pki.dnsCaaPolicy.policyMismatch && (
              <div className="p-3 rounded-xl bg-rose-950/30 border border-rose-500/40 text-rose-300">
                ⚠ WARNING: The active certificate was issued by an authority NOT declared in the domain's authoritative DNS CAA records. This may indicate fraudulent issuance or BGP DNS hijacking.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

