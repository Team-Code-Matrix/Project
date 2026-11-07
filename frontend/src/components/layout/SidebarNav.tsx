import React, { useState, useEffect } from 'react';
import {
  Shield,
  Search,
  LayoutDashboard,
  ShieldCheck,
  Cpu,
  Lock,
  Globe,
  Server,
  Network,
  FileCheck2,
  Cookie,
  Code2,
  KeyRound,
  GitFork,
  Download,
  Files,
  Tags,
  MapPin,
  Activity,
  FileText,
  History,
  Radio,
  Share2,
  FileSearch,
  BookOpen,
  Settings,
  PanelLeftClose,
  PanelLeftOpen,
  ChevronDown,
  ChevronRight,
  Menu,
  X,
} from 'lucide-react';

export interface NavModuleItem {
  id: string;
  label: string;
  icon: React.ElementType;
  badge?: string | null;
}

export interface NavGroup {
  id: string;
  title: string;
  items: NavModuleItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    id: 'dashboard',
    title: 'Dashboard',
    items: [
      { id: 'overview', label: 'Overview', icon: LayoutDashboard },
      { id: 'security-checks', label: 'Security Checks', icon: ShieldCheck, badge: 'Audit' },
      { id: 'tech-detection', label: 'Technology Detection', icon: Cpu },
    ],
  },
  {
    id: 'network-intelligence',
    title: 'Network Intelligence',
    items: [
      { id: 'cert-intel', label: 'Certificate Intelligence', icon: Lock, badge: 'RFC 5280' },
      { id: 'whois', label: 'WHOIS Lookup', icon: Globe },
      { id: 'ports', label: 'Port Assessment', icon: Server, badge: 'Passive' },
      { id: 'dns', label: 'DNS Analysis', icon: Network, badge: 'DNSSEC' },
    ],
  },
  {
    id: 'website-analysis',
    title: 'Website Analysis',
    items: [
      { id: 'headers', label: 'HTTP Headers', icon: FileCheck2, badge: 'CSP' },
      { id: 'cookies', label: 'Cookies', icon: Cookie },
      { id: 'scripts', label: 'Scripts & Libraries', icon: Code2 },
      { id: 'forms', label: 'Forms & Credential Analysis', icon: KeyRound, badge: 'Anti-Phish' },
      { id: 'redirects', label: 'Links & Redirects', icon: GitFork },
      { id: 'downloads', label: 'Downloads', icon: Download },
      { id: 'pages', label: 'Website Pages', icon: Files },
      { id: 'meta-tags', label: 'Meta Tags', icon: Tags },
    ],
  },
  {
    id: 'reports-intelligence',
    title: 'Reports & Intelligence',
    items: [
      { id: 'geo-locations', label: 'Geo Locations', icon: MapPin },
      { id: 'status-codes', label: 'HTTP Status Codes', icon: Activity },
      { id: 'reports', label: 'Security Reports', icon: FileText, badge: 'PDF' },
      { id: 'history', label: 'Scan History', icon: History },
      { id: 'threat-intel', label: 'Threat Intelligence', icon: Radio, badge: 'STIX 2.1' },
      { id: 'threat-graph', label: 'Threat Relationship Graph', icon: Share2, badge: 'Graph' },
      { id: 'forensics', label: 'Forensic Investigation', icon: FileSearch, badge: 'Vault' },
    ],
  },
  {
    id: 'system',
    title: 'System',
    items: [
      { id: 'methodology', label: 'Methodology', icon: BookOpen },
      { id: 'settings', label: 'Settings', icon: Settings },
    ],
  },
];

export interface SidebarNavProps {
  onScanClick: () => void;
  onOpenMethodology?: () => void;
  onOpenHistory?: () => void;
  isExpanded?: boolean;
  onToggleExpand?: () => void;
  activeModule?: string;
  onSelectModule?: (moduleId: string) => void;
  activeHostname?: string;
  activeTrustScore?: number;
}

export const SidebarNav: React.FC<SidebarNavProps> = ({
  onScanClick,
  onOpenMethodology,
  onOpenHistory,
  isExpanded: controlledExpanded,
  onToggleExpand,
  activeModule = 'overview',
  onSelectModule,
  activeHostname,
  activeTrustScore,
}) => {
  const [internalExpanded, setInternalExpanded] = useState(false);
  const isExpanded = controlledExpanded !== undefined ? controlledExpanded : internalExpanded;
  const toggleExpand = onToggleExpand || (() => setInternalExpanded(!internalExpanded));

  // Accordion open/collapse states for groups
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({
    dashboard: true,
    'network-intelligence': true,
    'website-analysis': true,
    'reports-intelligence': true,
    system: true,
  });

  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const toggleGroup = (groupId: string) => {
    setOpenGroups((prev) => ({
      ...prev,
      [groupId]: !prev[groupId],
    }));
  };

  const handleItemClick = (moduleId: string) => {
    if (onSelectModule) {
      onSelectModule(moduleId);
    }
    setMobileMenuOpen(false);
  };

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

  return (
    <>
      {/* ========================================================================= */}
      {/* 1. DESKTOP FLOATING PILL SIDEBAR                                          */}
      {/* ========================================================================= */}
      <aside
        aria-label="TrustShield Navigation"
        className={`hidden md:flex fixed left-4 top-5 bottom-5 z-40 flex-col justify-between py-4 bg-[#0B100E]/92 backdrop-blur-2xl border border-white/[0.08] shadow-[0_20px_50px_rgba(0,0,0,0.75)] rounded-[28px] ring-1 ring-white/[0.04] transition-[width] duration-300 ease-[cubic-bezier(0.2,0,0,1)] select-none overflow-hidden ${
          isExpanded ? 'w-[264px] px-3.5' : 'w-[72px] px-2.5'
        }`}
      >
        {/* Top: Brand Mark & Quick Scan Action */}
        <div className="flex flex-col gap-3 pb-3 border-b border-shield-border/40 shrink-0">
          <button
            type="button"
            onClick={() => handleItemClick('overview')}
            className={`flex items-center gap-3 py-1 group cursor-pointer transition-all ${
              isExpanded ? 'px-1' : 'justify-center'
            }`}
            title="Trust Shield Cyber Intelligence"
          >
            <div className="relative p-2.5 rounded-2xl bg-[#141D18] border border-shield-border group-hover:border-emerald-500/50 transition-all shadow-clay-sm flex-shrink-0">
              <Shield className="w-5 h-5 text-emerald-400 group-hover:scale-105 transition-transform" />
              <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_#10B981] animate-pulse" />
            </div>

            {isExpanded && (
              <div className="flex flex-col overflow-hidden text-left animate-fadeIn">
                <span className="text-sm font-black tracking-tight text-shield-text-primary font-mono whitespace-nowrap">
                  TRUST SHIELD
                </span>
                <span className="text-[9px] font-mono tracking-widest text-emerald-400/90 uppercase font-semibold whitespace-nowrap">
                  INTEL ENGINE
                </span>
              </div>
            )}
          </button>

          {/* Primary CTA: "Scan URL" Button */}
          {isExpanded ? (
            <button
              type="button"
              onClick={onScanClick}
              className="w-full py-2.5 px-3 rounded-2xl bg-gradient-to-r from-emerald-400 via-emerald-500 to-teal-500 hover:from-[#FCE7B2] hover:via-[#F3D081] hover:to-[#D4A747] text-[#080B09] font-black text-xs font-mono flex items-center justify-between shadow-[0_4px_20px_rgba(16,185,129,0.35)] hover:shadow-[0_6px_28px_rgba(243,208,129,0.55)] hover:scale-[1.02] active:scale-[0.98] transition-all cursor-pointer group"
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
                className="w-11 h-11 rounded-2xl bg-gradient-to-br from-emerald-400 to-emerald-600 hover:from-[#FCE7B2] hover:to-[#F3D081] text-[#080B09] font-black flex items-center justify-center shadow-[0_4px_18px_rgba(16,185,129,0.4)] hover:shadow-[0_6px_24px_rgba(243,208,129,0.6)] hover:scale-105 active:scale-95 transition-all cursor-pointer"
                aria-label="Scan Target URL"
              >
                <Search className="w-4 h-4 text-[#080B09]" />
              </button>
              <div className="absolute left-[calc(100%+14px)] top-1/2 -translate-y-1/2 px-3 py-1.5 rounded-xl bg-[#141D18] border border-shield-border text-xs font-mono font-bold text-emerald-400 whitespace-nowrap shadow-clay-card pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity z-50 flex items-center gap-2">
                <span>Scan URL</span>
                <span className="px-1.5 py-0.5 rounded bg-black/40 text-[10px] text-shield-text-secondary">
                  [S]
                </span>
              </div>
            </div>
          )}

          {/* Active Target Banner (When Expanded) */}
          {isExpanded && activeHostname && (
            <div className="px-2.5 py-1.5 rounded-xl bg-[#141D18]/80 border border-shield-border/60 flex items-center justify-between text-[11px] font-mono animate-fadeIn">
              <span className="text-shield-text-muted truncate max-w-[130px]" title={activeHostname}>
                {activeHostname}
              </span>
              {activeTrustScore !== undefined && (
                <span className="text-emerald-400 font-bold bg-emerald-950/60 px-1.5 py-0.5 rounded border border-emerald-500/30">
                  {activeTrustScore}/100
                </span>
              )}
            </div>
          )}
        </div>

        {/* Middle: Categorized Navigation Groups */}
        <nav className="flex-1 overflow-y-auto no-scrollbar py-2 space-y-3">
          {NAV_GROUPS.map((group) => {
            const isGroupOpen = openGroups[group.id] !== false;

            return (
              <div key={group.id} className="space-y-1">
                {/* Group Accordion Header (Expanded View Only) */}
                {isExpanded ? (
                  <button
                    type="button"
                    onClick={() => toggleGroup(group.id)}
                    className="w-full px-2 py-1 flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-shield-text-muted hover:text-shield-accent-light transition-colors cursor-pointer"
                  >
                    <span>{group.title}</span>
                    {isGroupOpen ? (
                      <ChevronDown className="w-3 h-3" />
                    ) : (
                      <ChevronRight className="w-3 h-3" />
                    )}
                  </button>
                ) : (
                  <div className="my-1.5 mx-auto w-6 border-t border-shield-border/40" />
                )}

                {/* Group Items */}
                {(isExpanded ? isGroupOpen : true) && (
                  <div className="space-y-0.5">
                    {group.items.map((item) => {
                      const Icon = item.icon;
                      const isActive = activeModule === item.id;

                      return (
                        <div key={item.id} className="relative group">
                          <button
                            type="button"
                            onClick={() => handleItemClick(item.id)}
                            className={`relative flex items-center transition-all cursor-pointer rounded-2xl ${
                              isExpanded
                                ? 'w-full px-3 py-2 gap-3 text-left'
                                : 'w-11 h-11 mx-auto justify-center'
                            } ${
                              isActive
                                ? 'bg-gradient-to-r from-emerald-500/20 via-emerald-500/10 to-transparent border border-emerald-500/30 text-emerald-400 font-bold shadow-[0_0_16px_rgba(16,185,129,0.12)]'
                                : 'text-shield-text-secondary hover:text-shield-text-primary hover:bg-white/[0.05] border border-transparent'
                            }`}
                          >
                            {/* Glowing Left Indicator */}
                            {isActive && (
                              <span
                                className={`absolute rounded-full bg-emerald-400 shadow-[0_0_10px_#10B981] ${
                                  isExpanded
                                    ? 'left-1 top-1/2 -translate-y-1/2 w-1 h-4'
                                    : '-left-1 top-1/2 -translate-y-1/2 w-1.5 h-5'
                                }`}
                              />
                            )}

                            <Icon
                              className={`w-4 h-4 flex-shrink-0 transition-all ${
                                isActive
                                  ? 'text-emerald-400 scale-110 drop-shadow-[0_0_8px_rgba(16,185,129,0.5)]'
                                  : 'text-shield-text-secondary group-hover:text-shield-text-primary'
                              }`}
                            />

                            {isExpanded && (
                              <span className="text-xs font-mono tracking-wide truncate flex-1">
                                {item.label}
                              </span>
                            )}

                            {isExpanded && item.badge && (
                              <span className="px-1.5 py-0.5 rounded-full bg-emerald-950/70 text-[9px] font-mono font-bold text-emerald-400 border border-emerald-500/30 shrink-0">
                                {item.badge}
                              </span>
                            )}
                          </button>

                          {/* Hover Tooltip in Collapsed Mode */}
                          {!isExpanded && (
                            <div className="absolute left-[calc(100%+14px)] top-1/2 -translate-y-1/2 px-3 py-1.5 rounded-xl bg-[#141D18] border border-shield-border text-xs font-mono font-medium text-shield-text-primary whitespace-nowrap shadow-clay-card pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity z-50 flex items-center gap-2">
                              <span className="text-[10px] text-shield-text-muted uppercase">
                                {group.title}:
                              </span>
                              <span className="text-emerald-400 font-bold">{item.label}</span>
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
                  </div>
                )}
              </div>
            );
          })}
        </nav>

        {/* Bottom: Collapse / Expand Action */}
        <div className={`pt-2 border-t border-shield-border/40 shrink-0 ${isExpanded ? 'px-1' : ''}`}>
          <button
            type="button"
            onClick={toggleExpand}
            className={`w-full py-2 rounded-2xl text-shield-text-muted hover:text-shield-text-primary hover:bg-white/[0.05] transition-all flex items-center cursor-pointer ${
              isExpanded ? 'px-2 justify-between' : 'justify-center'
            }`}
            title={isExpanded ? 'Collapse Sidebar' : 'Expand Sidebar'}
          >
            <div className="flex items-center gap-2">
              {isExpanded ? (
                <PanelLeftClose className="w-4 h-4 text-shield-text-secondary hover:text-emerald-400 transition-colors" />
              ) : (
                <PanelLeftOpen className="w-4 h-4 text-shield-text-secondary hover:text-emerald-400 transition-colors" />
              )}
              {isExpanded && (
                <span className="text-[11px] font-mono text-shield-text-muted">Collapse</span>
              )}
            </div>
            {isExpanded && (
              <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_6px_#10B981] animate-pulse" />
            )}
          </button>
        </div>
      </aside>

      {/* ========================================================================= */}
      {/* 2. MOBILE BOTTOM FLOATING DOCK                                            */}
      {/* ========================================================================= */}
      <div className="md:hidden fixed bottom-3 left-3 right-3 z-50 flex items-center justify-between px-4 py-2.5 rounded-3xl bg-[#0B100E]/95 backdrop-blur-2xl border border-white/[0.1] shadow-[0_10px_35px_rgba(0,0,0,0.85)]">
        <button
          type="button"
          onClick={() => handleItemClick('overview')}
          className={`p-2 rounded-2xl flex flex-col items-center gap-0.5 transition-all ${
            activeModule === 'overview' ? 'text-emerald-400' : 'text-shield-text-secondary'
          }`}
        >
          <LayoutDashboard className="w-5 h-5" />
          <span className="text-[9px] font-mono font-medium">Overview</span>
        </button>

        <button
          type="button"
          onClick={() => handleItemClick('security-checks')}
          className={`p-2 rounded-2xl flex flex-col items-center gap-0.5 transition-all ${
            activeModule === 'security-checks' ? 'text-emerald-400' : 'text-shield-text-secondary'
          }`}
        >
          <ShieldCheck className="w-5 h-5" />
          <span className="text-[9px] font-mono font-medium">Checks</span>
        </button>

        {/* Primary Center Scan Button */}
        <button
          type="button"
          onClick={onScanClick}
          className="relative -top-3 p-3.5 rounded-2xl bg-gradient-to-br from-emerald-400 to-emerald-600 text-[#080B09] shadow-[0_4px_22px_rgba(16,185,129,0.55)] active:scale-95 transition-all cursor-pointer"
          aria-label="Scan Target URL"
        >
          <Search className="w-5 h-5 text-[#080B09] font-black" />
        </button>

        <button
          type="button"
          onClick={() => handleItemClick('cert-intel')}
          className={`p-2 rounded-2xl flex flex-col items-center gap-0.5 transition-all ${
            activeModule === 'cert-intel' ? 'text-emerald-400' : 'text-shield-text-secondary'
          }`}
        >
          <Lock className="w-5 h-5" />
          <span className="text-[9px] font-mono font-medium">Cert PKI</span>
        </button>

        <button
          type="button"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className={`p-2 rounded-2xl flex flex-col items-center gap-0.5 transition-all ${
            mobileMenuOpen ? 'text-emerald-400' : 'text-shield-text-secondary'
          }`}
        >
          {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          <span className="text-[9px] font-mono font-medium">Modules</span>
        </button>
      </div>

      {/* ========================================================================= */}
      {/* 3. MOBILE FULL MODULES DRAWER                                             */}
      {/* ========================================================================= */}
      {mobileMenuOpen && (
        <div className="md:hidden fixed inset-0 z-40 bg-black/80 backdrop-blur-md flex flex-col justify-end p-3 pb-22 animate-fadeIn">
          <div className="clay-card rounded-3xl p-5 border border-shield-border/80 max-h-[80vh] flex flex-col space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-shield-border/40">
              <span className="text-xs font-mono font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-400" />
                Security Analysis Modules
              </span>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                className="p-1 rounded-lg text-shield-text-secondary hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto no-scrollbar space-y-4 text-left">
              {NAV_GROUPS.map((group) => (
                <div key={group.id} className="space-y-2">
                  <div className="text-[10px] font-mono uppercase tracking-wider text-shield-accent-light">
                    {group.title}
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                    {group.items.map((item) => {
                      const Icon = item.icon;
                      const isActive = activeModule === item.id;
                      return (
                        <button
                          key={item.id}
                          type="button"
                          onClick={() => handleItemClick(item.id)}
                          className={`p-2.5 rounded-xl border flex items-center gap-2 transition-all text-left ${
                            isActive
                              ? 'bg-emerald-950/80 border-emerald-500 text-emerald-400 font-bold'
                              : 'bg-shield-surface/60 border-shield-border/60 text-shield-text-primary hover:bg-shield-surface'
                          }`}
                        >
                          <Icon className="w-4 h-4 shrink-0 text-shield-accent-light" />
                          <span className="truncate">{item.label}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  );
};
