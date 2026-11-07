import React, { useState, useEffect } from 'react';
import {
  Shield,
  Search,
  LayoutDashboard,
  Layers,
  Workflow,
  Radio,
  Info,
  BookOpen,
  History,
  PanelLeftClose,
  PanelLeftOpen,
  Menu,
  X,
} from 'lucide-react';

export interface SidebarNavProps {
  onScanClick: () => void;
  onOpenMethodology?: () => void;
  onOpenHistory?: () => void;
  isExpanded?: boolean;
  onToggleExpand?: () => void;
}

export const SidebarNav: React.FC<SidebarNavProps> = ({
  onScanClick,
  onOpenMethodology,
  onOpenHistory,
  isExpanded: controlledExpanded,
  onToggleExpand,
}) => {
  // Local state if uncontrolled, or controlled by parent
  const [internalExpanded, setInternalExpanded] = useState(false);
  const isExpanded = controlledExpanded !== undefined ? controlledExpanded : internalExpanded;
  const toggleExpand = onToggleExpand || (() => setInternalExpanded(!internalExpanded));

  // Active section tracking
  const [activeSection, setActiveSection] = useState<string>('scanner');
  // Mobile popover/more sheet
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Monitor scroll position to update active section automatically
  useEffect(() => {
    const handleScroll = () => {
      const sections = ['scanner', 'features', 'how-it-works', 'threat-intel', 'about'];
      const scrollPos = window.scrollY + 200;

      for (const sectionId of sections) {
        const el = document.getElementById(sectionId);
        if (el) {
          const top = el.offsetTop;
          const height = el.offsetHeight;
          if (scrollPos >= top && scrollPos < top + height) {
            setActiveSection(sectionId);
            break;
          }
        }
      }
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // Global keyboard shortcut: pressing 'S' or Cmd+K / Ctrl+K triggers scan
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (
        (e.key === 's' || e.key === 'S') &&
        !['INPUT', 'TEXTAREA'].includes((e.target as HTMLElement)?.tagName)
      ) {
        e.preventDefault();
        onScanClick();
      }
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        onScanClick();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onScanClick]);

  const navItems = [
    {
      id: 'scanner',
      label: 'Overview',
      icon: LayoutDashboard,
      href: '#scanner',
      badge: null,
    },
    {
      id: 'features',
      label: 'Features',
      icon: Layers,
      href: '#features',
      badge: '6 Models',
    },
    {
      id: 'how-it-works',
      label: 'How It Works',
      icon: Workflow,
      href: '#how-it-works',
      badge: null,
    },
    {
      id: 'threat-intel',
      label: 'Threat Intel',
      icon: Radio,
      href: '#threat-intel',
      badge: 'Live',
    },
    {
      id: 'about',
      label: 'About',
      icon: Info,
      href: '#about',
      badge: null,
    },
  ];

  const handleNavClick = (href: string, id: string) => {
    setActiveSection(id);
    const targetEl = document.querySelector(href);
    if (targetEl) {
      targetEl.scrollIntoView({ behavior: 'smooth' });
    }
    setMobileMenuOpen(false);
  };

  return (
    <>
      {/* ========================================================================= */}
      {/* 1. DESKTOP FLOATING PILL SIDEBAR (Hidden on mobile < md)                 */}
      {/* Inspired by the floating glassmorphic pill aesthetic from reference image */}
      {/* ========================================================================= */}
      <aside
        aria-label="Main Navigation"
        className={`hidden md:flex fixed left-4 top-6 bottom-6 z-40 flex-col justify-between py-5 bg-[#0B100E]/90 backdrop-blur-2xl border border-white/[0.08] shadow-[0_20px_50px_rgba(0,0,0,0.7)] rounded-[28px] ring-1 ring-white/[0.04] transition-[width] duration-300 ease-[cubic-bezier(0.2,0,0,1)] select-none overflow-visible ${
          isExpanded ? 'w-[240px] px-3.5' : 'w-[72px] px-2.5'
        }`}
      >
        {/* Top: Brand Logo & Primary Action CTA */}
        <div className="flex flex-col gap-4">
          {/* Brand Mark */}
          <a
            href="#scanner"
            onClick={(e) => {
              e.preventDefault();
              handleNavClick('#scanner', 'scanner');
            }}
            className={`flex items-center gap-3 py-1 group cursor-pointer transition-all ${
              isExpanded ? 'px-2' : 'justify-center'
            }`}
            title="Trust Shield Cyber Intelligence"
          >
            <div className="relative p-2.5 rounded-2xl bg-[#141D18] border border-shield-border group-hover:border-emerald-500/50 transition-all shadow-clay-sm flex-shrink-0">
              <Shield className="w-5 h-5 text-emerald-400 group-hover:scale-105 transition-transform" />
              <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_#10B981] animate-pulse" />
            </div>

            {isExpanded && (
              <div className="flex flex-col overflow-hidden text-left animate-fadeIn">
                <span className="text-sm font-black tracking-tight text-shield-text-primary font-mono whitespace-nowrap flex items-center gap-1.5">
                  TRUST SHIELD
                </span>
                <span className="text-[9px] font-mono tracking-widest text-emerald-400/90 uppercase font-semibold whitespace-nowrap">
                  INTEL ENGINE
                </span>
              </div>
            )}
          </a>

          {/* Primary CTA: "Scan URL" Button */}
          {isExpanded ? (
            <button
              type="button"
              onClick={onScanClick}
              className="w-full py-3 px-3.5 rounded-2xl bg-gradient-to-r from-emerald-400 via-emerald-500 to-teal-500 hover:from-emerald-300 hover:to-teal-400 text-[#080B09] font-black text-xs font-mono flex items-center justify-between shadow-[0_4px_20px_rgba(16,185,129,0.35)] hover:shadow-[0_6px_28px_rgba(16,185,129,0.55)] hover:scale-[1.02] active:scale-[0.98] transition-all cursor-pointer group"
            >
              <div className="flex items-center gap-2">
                <Search className="w-4 h-4 text-[#080B09] group-hover:scale-110 transition-transform" />
                <span className="tracking-wide">Scan URL</span>
              </div>
              <span className="px-1.5 py-0.5 rounded-md bg-[#080B09]/20 text-[10px] font-bold">
                S
              </span>
            </button>
          ) : (
            <div className="relative group flex justify-center">
              <button
                type="button"
                onClick={onScanClick}
                className="w-12 h-12 rounded-2xl bg-gradient-to-br from-emerald-400 to-emerald-600 hover:from-emerald-300 hover:to-emerald-500 text-[#080B09] font-black flex items-center justify-center shadow-[0_4px_18px_rgba(16,185,129,0.4)] hover:shadow-[0_6px_24px_rgba(16,185,129,0.6)] hover:scale-105 active:scale-95 transition-all cursor-pointer"
                aria-label="Scan Target URL"
              >
                <Search className="w-5 h-5 text-[#080B09]" />
              </button>
              {/* Tooltip on hover */}
              <div className="absolute left-[calc(100%+14px)] top-1/2 -translate-y-1/2 px-3 py-1.5 rounded-xl bg-[#141D18] border border-shield-border text-xs font-mono font-bold text-emerald-400 whitespace-nowrap shadow-clay-card pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity z-50 flex items-center gap-2">
                <span>Scan URL</span>
                <span className="px-1.5 py-0.5 rounded bg-black/40 text-[10px] text-shield-text-secondary">
                  [S]
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Middle: Core Navigation Links */}
        <nav className="flex-1 flex flex-col justify-center gap-1.5 py-3 overflow-visible">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeSection === item.id;

            return (
              <div key={item.id} className="relative group">
                <a
                  href={item.href}
                  onClick={(e) => {
                    e.preventDefault();
                    handleNavClick(item.href, item.id);
                  }}
                  className={`relative flex items-center transition-all cursor-pointer rounded-2xl ${
                    isExpanded
                      ? 'w-full px-3.5 py-2.5 gap-3.5'
                      : 'w-12 h-12 mx-auto justify-center'
                  } ${
                    isActive
                      ? 'bg-gradient-to-r from-emerald-500/20 via-emerald-500/8 to-transparent border border-emerald-500/30 text-emerald-400 font-bold shadow-[0_0_20px_rgba(16,185,129,0.15)]'
                      : 'text-shield-text-secondary hover:text-shield-text-primary hover:bg-white/[0.05] border border-transparent'
                  }`}
                >
                  {/* Glowing Vertical Indicator Bar on Left (Directly from reference image style) */}
                  {isActive && (
                    <span
                      className={`absolute rounded-full bg-emerald-400 shadow-[0_0_10px_#10B981] ${
                        isExpanded
                          ? 'left-1 top-1/2 -translate-y-1/2 w-1 h-5'
                          : '-left-1 top-1/2 -translate-y-1/2 w-1.5 h-6'
                      }`}
                    />
                  )}

                  <Icon
                    className={`w-5 h-5 flex-shrink-0 transition-all ${
                      isActive
                        ? 'text-emerald-400 scale-105 drop-shadow-[0_0_8px_rgba(16,185,129,0.5)]'
                        : 'text-shield-text-secondary group-hover:text-shield-text-primary group-hover:scale-105'
                    }`}
                  />

                  {isExpanded && (
                    <span className="text-xs font-mono tracking-wide truncate flex-1 text-left">
                      {item.label}
                    </span>
                  )}

                  {isExpanded && item.badge && (
                    <span className="px-1.5 py-0.5 rounded-full bg-emerald-950/70 text-[9px] font-mono font-bold text-emerald-400 border border-emerald-500/30">
                      {item.badge}
                    </span>
                  )}
                </a>

                {/* Hover Tooltip in collapsed view */}
                {!isExpanded && (
                  <div className="absolute left-[calc(100%+14px)] top-1/2 -translate-y-1/2 px-3 py-1.5 rounded-xl bg-[#141D18] border border-shield-border text-xs font-mono font-medium text-shield-text-primary whitespace-nowrap shadow-clay-card pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity z-50 flex items-center gap-2">
                    <span>{item.label}</span>
                    {item.badge && (
                      <span className="px-1.5 py-0.5 rounded-full bg-emerald-950/70 text-[9px] text-emerald-400 border border-emerald-500/30">
                        {item.badge}
                      </span>
                    )}
                  </div>
                )}
              </div>
            );
          })}

          {/* Divider */}
          <div className={`my-2 border-t border-shield-border/40 ${isExpanded ? 'mx-2' : 'mx-1'}`} />

          {/* Methodology Trigger */}
          {onOpenMethodology && (
            <div className="relative group">
              <button
                type="button"
                onClick={() => {
                  onOpenMethodology();
                  setActiveSection('methodology');
                }}
                className={`relative flex items-center transition-all cursor-pointer rounded-2xl ${
                  isExpanded
                    ? 'w-full px-3.5 py-2.5 gap-3.5 text-left'
                    : 'w-12 h-12 mx-auto justify-center'
                } ${
                  activeSection === 'methodology'
                    ? 'bg-gradient-to-r from-emerald-500/20 via-emerald-500/8 to-transparent border border-emerald-500/30 text-emerald-400 font-bold'
                    : 'text-shield-text-secondary hover:text-shield-text-primary hover:bg-white/[0.05] border border-transparent'
                }`}
              >
                {activeSection === 'methodology' && (
                  <span
                    className={`absolute rounded-full bg-emerald-400 shadow-[0_0_10px_#10B981] ${
                      isExpanded
                        ? 'left-1 top-1/2 -translate-y-1/2 w-1 h-5'
                        : '-left-1 top-1/2 -translate-y-1/2 w-1.5 h-6'
                    }`}
                  />
                )}
                <BookOpen className="w-5 h-5 flex-shrink-0 text-shield-text-secondary group-hover:text-emerald-400 transition-colors" />
                {isExpanded && (
                  <span className="text-xs font-mono tracking-wide truncate">
                    Methodology
                  </span>
                )}
              </button>
              {!isExpanded && (
                <div className="absolute left-[calc(100%+14px)] top-1/2 -translate-y-1/2 px-3 py-1.5 rounded-xl bg-[#141D18] border border-shield-border text-xs font-mono font-medium text-shield-text-primary whitespace-nowrap shadow-clay-card pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity z-50">
                  Methodology
                </div>
              )}
            </div>
          )}

          {/* History Drawer Trigger */}
          {onOpenHistory && (
            <div className="relative group">
              <button
                type="button"
                onClick={() => {
                  onOpenHistory();
                  setActiveSection('history');
                }}
                className={`relative flex items-center transition-all cursor-pointer rounded-2xl ${
                  isExpanded
                    ? 'w-full px-3.5 py-2.5 gap-3.5 text-left'
                    : 'w-12 h-12 mx-auto justify-center'
                } ${
                  activeSection === 'history'
                    ? 'bg-gradient-to-r from-emerald-500/20 via-emerald-500/8 to-transparent border border-emerald-500/30 text-emerald-400 font-bold'
                    : 'text-shield-text-secondary hover:text-shield-text-primary hover:bg-white/[0.05] border border-transparent'
                }`}
              >
                {activeSection === 'history' && (
                  <span
                    className={`absolute rounded-full bg-emerald-400 shadow-[0_0_10px_#10B981] ${
                      isExpanded
                        ? 'left-1 top-1/2 -translate-y-1/2 w-1 h-5'
                        : '-left-1 top-1/2 -translate-y-1/2 w-1.5 h-6'
                    }`}
                  />
                )}
                <History className="w-5 h-5 flex-shrink-0 text-shield-text-secondary group-hover:text-emerald-400 transition-colors" />
                {isExpanded && (
                  <span className="text-xs font-mono tracking-wide truncate">
                    History
                  </span>
                )}
              </button>
              {!isExpanded && (
                <div className="absolute left-[calc(100%+14px)] top-1/2 -translate-y-1/2 px-3 py-1.5 rounded-xl bg-[#141D18] border border-shield-border text-xs font-mono font-medium text-shield-text-primary whitespace-nowrap shadow-clay-card pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity z-50">
                  Scan History
                </div>
              )}
            </div>
          )}
        </nav>

        {/* Bottom: Collapse / Expand Toggle & System Pulse */}
        <div className={`flex flex-col gap-2 pt-2 ${isExpanded ? 'border-t border-shield-border/40' : ''}`}>
          <button
            type="button"
            onClick={toggleExpand}
            className={`w-full py-2 rounded-2xl text-shield-text-muted hover:text-shield-text-primary hover:bg-white/[0.05] transition-all flex items-center cursor-pointer ${
              isExpanded ? 'px-3 justify-between' : 'justify-center'
            }`}
            title={isExpanded ? 'Collapse Sidebar' : 'Expand Sidebar'}
          >
            <div className="flex items-center gap-2.5">
              {isExpanded ? (
                <PanelLeftClose className="w-4 h-4 text-shield-text-secondary hover:text-emerald-400 transition-colors" />
              ) : (
                <PanelLeftOpen className="w-4 h-4 text-shield-text-secondary hover:text-emerald-400 transition-colors" />
              )}
              {isExpanded && (
                <span className="text-[11px] font-mono text-shield-text-muted">
                  Collapse
                </span>
              )}
            </div>
            {isExpanded && (
              <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_6px_#10B981] animate-pulse" />
            )}
          </button>
        </div>
      </aside>

      {/* ========================================================================= */}
      {/* 2. MOBILE BOTTOM FLOATING DOCK (Visible only on < md)                     */}
      {/* Preserves 100% of the screen estate for the scanner tool on mobile        */}
      {/* ========================================================================= */}
      <div className="md:hidden fixed bottom-3 left-3 right-3 z-50 flex items-center justify-between px-4 py-2.5 rounded-3xl bg-[#0B100E]/95 backdrop-blur-2xl border border-white/[0.1] shadow-[0_10px_35px_rgba(0,0,0,0.85)]">
        {/* Overview */}
        <a
          href="#scanner"
          onClick={(e) => {
            e.preventDefault();
            handleNavClick('#scanner', 'scanner');
          }}
          className={`p-2 rounded-2xl flex flex-col items-center gap-0.5 transition-all ${
            activeSection === 'scanner' ? 'text-emerald-400' : 'text-shield-text-secondary'
          }`}
        >
          <LayoutDashboard className="w-5 h-5" />
          <span className="text-[9px] font-mono font-medium">Overview</span>
        </a>

        {/* Features */}
        <a
          href="#features"
          onClick={(e) => {
            e.preventDefault();
            handleNavClick('#features', 'features');
          }}
          className={`p-2 rounded-2xl flex flex-col items-center gap-0.5 transition-all ${
            activeSection === 'features' ? 'text-emerald-400' : 'text-shield-text-secondary'
          }`}
        >
          <Layers className="w-5 h-5" />
          <span className="text-[9px] font-mono font-medium">Features</span>
        </a>

        {/* Primary Center Scan Button */}
        <button
          type="button"
          onClick={onScanClick}
          className="relative -top-4 p-3.5 rounded-2xl bg-gradient-to-br from-emerald-400 to-emerald-600 text-[#080B09] shadow-[0_4px_22px_rgba(16,185,129,0.55)] active:scale-95 transition-all cursor-pointer"
          aria-label="Scan Target URL"
        >
          <Search className="w-5 h-5 text-[#080B09] font-black" />
        </button>

        {/* Threat Intel */}
        <a
          href="#threat-intel"
          onClick={(e) => {
            e.preventDefault();
            handleNavClick('#threat-intel', 'threat-intel');
          }}
          className={`p-2 rounded-2xl flex flex-col items-center gap-0.5 transition-all ${
            activeSection === 'threat-intel' ? 'text-emerald-400' : 'text-shield-text-secondary'
          }`}
        >
          <Radio className="w-5 h-5" />
          <span className="text-[9px] font-mono font-medium">Intel</span>
        </a>

        {/* More Menu Drawer Trigger */}
        <button
          type="button"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className={`p-2 rounded-2xl flex flex-col items-center gap-0.5 transition-all ${
            mobileMenuOpen ? 'text-emerald-400' : 'text-shield-text-secondary'
          }`}
        >
          {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          <span className="text-[9px] font-mono font-medium">Menu</span>
        </button>
      </div>

      {/* Mobile Drawer Overlay */}
      {mobileMenuOpen && (
        <div className="md:hidden fixed inset-0 z-40 bg-black/80 backdrop-blur-md flex flex-col justify-end p-4 pb-24 animate-fadeIn">
          <div className="clay-card rounded-3xl p-5 border border-shield-border/80 space-y-3">
            <div className="flex items-center justify-between pb-3 border-b border-shield-border/40">
              <span className="text-xs font-mono font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-400" />
                Trust Shield Navigation
              </span>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                className="p-1 rounded-lg text-shield-text-secondary hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs font-mono">
              <a
                href="#how-it-works"
                onClick={(e) => {
                  e.preventDefault();
                  handleNavClick('#how-it-works', 'how-it-works');
                }}
                className="p-3 rounded-xl bg-shield-surface/60 border border-shield-border/60 text-shield-text-primary flex items-center gap-2"
              >
                <Workflow className="w-4 h-4 text-emerald-400" />
                <span>How It Works</span>
              </a>

              <a
                href="#about"
                onClick={(e) => {
                  e.preventDefault();
                  handleNavClick('#about', 'about');
                }}
                className="p-3 rounded-xl bg-shield-surface/60 border border-shield-border/60 text-shield-text-primary flex items-center gap-2"
              >
                <Info className="w-4 h-4 text-emerald-400" />
                <span>About</span>
              </a>

              {onOpenMethodology && (
                <button
                  type="button"
                  onClick={() => {
                    onOpenMethodology();
                    setMobileMenuOpen(false);
                  }}
                  className="p-3 rounded-xl bg-shield-surface/60 border border-shield-border/60 text-shield-text-primary flex items-center gap-2 text-left"
                >
                  <BookOpen className="w-4 h-4 text-emerald-400" />
                  <span>Methodology</span>
                </button>
              )}

              {onOpenHistory && (
                <button
                  type="button"
                  onClick={() => {
                    onOpenHistory();
                    setMobileMenuOpen(false);
                  }}
                  className="p-3 rounded-xl bg-shield-surface/60 border border-shield-border/60 text-shield-text-primary flex items-center gap-2 text-left"
                >
                  <History className="w-4 h-4 text-emerald-400" />
                  <span>Scan History</span>
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
};
