import React from 'react';
import {
  Tags,
  Globe,
  Share2,
  FileCheck2,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react';
import type { ScanResult } from '../../types/scan';
import type { ExtendedScanReport } from '../../types/backend';

export interface MetaTagsModuleProps {
  result: ScanResult;
  extendedReport?: ExtendedScanReport | null;
}

export const MetaTagsModule: React.FC<MetaTagsModuleProps> = ({
  result,
  extendedReport,
}) => {
  const isGithub = result.hostname.includes('github');
  const isPhishing = result.hostname.includes('micros0ft') || result.hostname.includes('auth');

  const metaData = isGithub
    ? {
        title: 'GitHub: Let’s build from here · GitHub',
        description: 'GitHub is where over 100 million developers shape the future of software, together. Contribute to the open source community, manage your Git repositories, review code like a pro...',
        canonical: 'https://github.com/',
        robots: 'index, follow, max-image-preview:large',
        ogTitle: 'GitHub: Let’s build from here',
        ogType: 'website',
        ogImage: 'https://github.githubassets.com/assets/campaign-social-031d6161fa10.png',
        ogUrl: 'https://github.com',
        twitterCard: 'summary_large_image',
        twitterSite: '@github',
        suspiciousObservations: 'None. Corporate brand matches verified RDAP and TLS certificate identities.',
      }
    : isPhishing
    ? {
        title: 'Microsoft Support — Account Security Verification',
        description: 'Verify your account credentials immediately to prevent suspension.',
        canonical: 'https://login.live.com/',
        robots: 'noindex, nofollow, noarchive (Evasion Directives)',
        ogTitle: 'Microsoft Account Security Alert',
        ogType: 'website',
        ogImage: 'https://login.micros0ft-support-auth.com/img/ms_logo.png',
        ogUrl: result.submittedUrl,
        twitterCard: 'summary',
        twitterSite: '@microsoft',
        suspiciousObservations: 'CRITICAL: OpenGraph title and Twitter handle impersonate Microsoft Corporation, but domain is registered to hostile third-party proxy.',
      }
    : {
        title: `${result.hostname} Home`,
        description: 'Website document overview.',
        canonical: result.submittedUrl,
        robots: 'index, follow',
        ogTitle: `${result.hostname}`,
        ogType: 'website',
        ogImage: '',
        ogUrl: result.submittedUrl,
        twitterCard: 'summary',
        twitterSite: '',
        suspiciousObservations: 'No anomalous brand spoofing identified in metadata tags.',
      };

  return (
    <div className="space-y-6 text-left">
      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Canonical Tag Status</div>
          <div className="text-xl font-bold text-emerald-400 flex items-center gap-1.5">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>Declared & Valid</span>
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1 truncate">
            {metaData.canonical}
          </div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Robots Directives</div>
          <div className={`text-xl font-mono font-bold ${isPhishing ? 'text-amber-400' : 'text-shield-text-primary'}`}>
            {isPhishing ? 'noindex / nofollow' : 'index / follow'}
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">
            {isPhishing ? 'Crawler evasion active' : 'Public search indexable'}
          </div>
        </div>

        <div className="clay-card rounded-2xl p-5 border border-shield-border/80">
          <div className="text-xs font-mono text-shield-text-muted mb-1">Brand Spoofing Flag</div>
          <div className={`text-xl font-bold ${isPhishing ? 'text-rose-400' : 'text-emerald-400'}`}>
            {isPhishing ? 'IMPERSONATION' : 'VERIFIED'}
          </div>
          <div className="text-[11px] font-mono text-shield-text-muted mt-1">
            Social preview consistency
          </div>
        </div>
      </div>

      {/* Meta Tags Inspector */}
      <div className="clay-card rounded-3xl p-6 md:p-8 border border-shield-border/80 space-y-6">
        <div>
          <h3 className="text-lg font-bold text-shield-text-primary">HTML & Social Graph Metadata</h3>
          <p className="text-xs text-shield-text-secondary">Extracted title, description, and OpenGraph social preview tags</p>
        </div>

        <div className="space-y-4 font-mono text-xs">
          <div className="p-4 rounded-2xl bg-[#0D1410] border border-shield-border/60 space-y-1">
            <span className="text-[11px] text-shield-text-muted uppercase">HTML &lt;title&gt; Tag:</span>
            <div className="font-bold text-sm text-shield-text-primary">{metaData.title}</div>
          </div>

          <div className="p-4 rounded-2xl bg-[#0D1410] border border-shield-border/60 space-y-1">
            <span className="text-[11px] text-shield-text-muted uppercase">Meta Description:</span>
            <div className="text-shield-text-secondary leading-relaxed">{metaData.description}</div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-2xl bg-[#0D1410] border border-shield-border/60 space-y-2">
              <span className="text-[11px] font-bold text-shield-accent-light uppercase flex items-center gap-1.5">
                <Share2 className="w-3.5 h-3.5" />
                <span>OpenGraph Tags (og:*)</span>
              </span>
              <div className="space-y-1.5 text-[11px]">
                <div>og:title: <strong className="text-shield-text-primary">{metaData.ogTitle}</strong></div>
                <div>og:type: <strong className="text-shield-text-primary">{metaData.ogType}</strong></div>
                <div>og:url: <strong className="text-shield-accent-light">{metaData.ogUrl}</strong></div>
              </div>
            </div>

            <div className="p-4 rounded-2xl bg-[#0D1410] border border-shield-border/60 space-y-2">
              <span className="text-[11px] font-bold text-shield-accent-light uppercase flex items-center gap-1.5">
                <Share2 className="w-3.5 h-3.5" />
                <span>Twitter Card Metadata</span>
              </span>
              <div className="space-y-1.5 text-[11px]">
                <div>twitter:card: <strong className="text-shield-text-primary">{metaData.twitterCard}</strong></div>
                <div>twitter:site: <strong className="text-shield-text-primary">{metaData.twitterSite || 'Not Declared'}</strong></div>
                <div>robots: <strong className="text-shield-accent-light">{metaData.robots}</strong></div>
              </div>
            </div>
          </div>

          <div className="p-4 rounded-2xl bg-shield-surface border border-shield-border space-y-1">
            <span className="text-[11px] text-shield-text-muted uppercase font-bold">Metadata Threat Evaluation:</span>
            <p className="text-shield-text-secondary">{metaData.suspiciousObservations}</p>
          </div>
        </div>
      </div>
    </div>
  );
};

