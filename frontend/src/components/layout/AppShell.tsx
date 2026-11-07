import React, { useState, type ReactNode } from 'react';
import { SidebarNav } from './SidebarNav';
import { Footer } from './Footer';

interface AppShellProps {
  children: ReactNode;
  onScanClick: () => void;
  onOpenMethodology: () => void;
  onOpenReportModal: () => void;
  onOpenHistory?: () => void;
}

export const AppShell: React.FC<AppShellProps> = ({
  children,
  onScanClick,
  onOpenMethodology,
  onOpenReportModal,
  onOpenHistory,
}) => {
  // Sidebar expanded / collapsed state (persists during session)
  const [isSidebarExpanded, setIsSidebarExpanded] = useState(false);

  return (
    <div className="min-h-screen bg-shield-bg text-shield-text-primary flex flex-col relative selection:bg-emerald-500 selection:text-[#080B09] overflow-x-hidden">
      {/* Subtle organic ambient gradients */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0">
        <div className="absolute -top-40 left-1/2 -translate-x-1/2 w-[900px] h-[500px] bg-[#16271F]/25 blur-[140px] rounded-full" />
        <div className="absolute top-[40%] -left-40 w-[600px] h-[600px] bg-[#101A14]/30 blur-[160px] rounded-full" />
        <div className="absolute bottom-20 -right-40 w-[600px] h-[600px] bg-[#14231B]/20 blur-[150px] rounded-full" />
      </div>

      {/* Left-Aligned Floating Pill Sidebar Navigation (Desktop Floating Pill + Mobile Floating Bottom Dock) */}
      <SidebarNav
        onScanClick={onScanClick}
        onOpenMethodology={onOpenMethodology}
        onOpenHistory={onOpenHistory}
        isExpanded={isSidebarExpanded}
        onToggleExpand={() => setIsSidebarExpanded(!isSidebarExpanded)}
      />

      {/* Main Content Area: dynamically shifts left padding on desktop so the hero and URL scanner card remain perfectly centered in remaining viewport space */}
      <main
        className={`flex-1 w-full relative z-10 transition-[padding-left] duration-300 ease-[cubic-bezier(0.2,0,0,1)] ${
          isSidebarExpanded ? 'md:pl-[264px]' : 'md:pl-[96px]'
        } pb-24 md:pb-0`}
      >
        {children}
      </main>

      {/* Footer: matches main content viewport alignment */}
      <div
        className={`w-full relative z-10 transition-[padding-left] duration-300 ease-[cubic-bezier(0.2,0,0,1)] ${
          isSidebarExpanded ? 'md:pl-[264px]' : 'md:pl-[96px]'
        } pb-20 md:pb-0`}
      >
        <Footer
          onOpenMethodology={onOpenMethodology}
          onOpenReportModal={onOpenReportModal}
        />
      </div>
    </div>
  );
};
