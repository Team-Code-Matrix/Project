import { describe, it, expect } from 'vitest';
import { NAV_GROUPS } from './SidebarNav';

describe('Sidebar Navigation Architecture', () => {
  it('defines all 5 required navigation groups in order', () => {
    const groupIds = NAV_GROUPS.map((g) => g.id);
    expect(groupIds).toEqual([
      'dashboard',
      'network-intelligence',
      'website-analysis',
      'reports-intelligence',
      'system',
    ]);
  });

  it('contains all 24 required security modules with unique IDs', () => {
    const allItemIds = NAV_GROUPS.flatMap((g) => g.items.map((i) => i.id));
    const uniqueIds = new Set(allItemIds);

    expect(allItemIds.length).toBe(24);
    expect(uniqueIds.size).toBe(24);

    // Verify key security modules are present
    expect(uniqueIds.has('overview')).toBe(true);
    expect(uniqueIds.has('security-checks')).toBe(true);
    expect(uniqueIds.has('tech-detection')).toBe(true);
    expect(uniqueIds.has('cert-intel')).toBe(true);
    expect(uniqueIds.has('whois')).toBe(true);
    expect(uniqueIds.has('ports')).toBe(true);
    expect(uniqueIds.has('dns')).toBe(true);
    expect(uniqueIds.has('headers')).toBe(true);
    expect(uniqueIds.has('cookies')).toBe(true);
    expect(uniqueIds.has('scripts')).toBe(true);
    expect(uniqueIds.has('forms')).toBe(true);
    expect(uniqueIds.has('redirects')).toBe(true);
    expect(uniqueIds.has('downloads')).toBe(true);
    expect(uniqueIds.has('pages')).toBe(true);
    expect(uniqueIds.has('meta-tags')).toBe(true);
    expect(uniqueIds.has('geo-locations')).toBe(true);
    expect(uniqueIds.has('status-codes')).toBe(true);
    expect(uniqueIds.has('reports')).toBe(true);
    expect(uniqueIds.has('history')).toBe(true);
    expect(uniqueIds.has('threat-intel')).toBe(true);
    expect(uniqueIds.has('threat-graph')).toBe(true);
    expect(uniqueIds.has('forensics')).toBe(true);
    expect(uniqueIds.has('methodology')).toBe(true);
    expect(uniqueIds.has('settings')).toBe(true);
  });
});

