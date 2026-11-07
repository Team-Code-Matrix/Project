import { describe, it, expect } from 'vitest';
import { FastPathVerdictSchema, PkiIntelligenceSchema } from './backendSchemas';
import { EXTENDED_SCENARIOS } from '../services/extendedMockData';

describe('Backend Response Schemas', () => {
  it('validates FastPathVerdictSchema against real fixtures', () => {
    const fixture = EXTENDED_SCENARIOS['github.com'].fastPath;
    const result = FastPathVerdictSchema.safeParse(fixture);
    expect(result.success).toBe(true);
  });

  it('validates PkiIntelligenceSchema against real fixtures', () => {
    const fixture = EXTENDED_SCENARIOS['github.com'].pkiIntelligence;
    const result = PkiIntelligenceSchema.safeParse(fixture);
    expect(result.success).toBe(true);
  });

  it('validates compromised eMudhra PKI fixture schema', () => {
    const fixture = EXTENDED_SCENARIOS['expired-tls.untrusted-cdn-assets.org'].pkiIntelligence;
    const result = PkiIntelligenceSchema.safeParse(fixture);
    expect(result.success).toBe(true);
  });
});

