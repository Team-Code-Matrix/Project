import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from backend.threat_feed_ingestor import ThreatFeedIngestor

db_path = 'backend/data/trustshield_test_ingest.db'
if os.path.exists(db_path):
    os.remove(db_path)

ingestor = ThreatFeedIngestor(db_path)
print('[*] Ingestor initialized. Providers count:', len(ingestor.get_providers_status()))

# 1. Sync OpenPhish
print('[*] Syncing OpenPhish live feed...')
res = ingestor.sync_provider('openphish')
print('    OpenPhish sync result:', res)
assert res['status'] in ['ONLINE', 'CONNECTED'], f"Expected ONLINE or CONNECTED, got {res['status']}"
assert res['recordsLastSync'] > 0, "Expected > 0 records ingested"

# 2. Check threat feed records
all_threats = ingestor.get_threat_feed(limit=500)
print(f'[+] Ingested threat count: {len(all_threats)}')
assert len(all_threats) == res['recordsLastSync']
sample = all_threats[0]
print(f"    Sample IOC 0: ID={sample['id']}, Domain={sample['domain']}, Category={sample['category']}, Provider={sample['provider']}")

# 3. Check deduplication
print('[*] Testing deduplication by re-syncing OpenPhish...')
res2 = ingestor.sync_provider('openphish')
print('    Re-sync OpenPhish (new records expected: 0):', res2)
assert res2['recordsLastSync'] == 0, f"Expected 0 new records, got {res2['recordsLastSync']}"
assert len(ingestor.get_threat_feed(limit=500)) == len(all_threats), "Duplicate records were not rejected!"

# 4. Check aggregated metrics
metrics = ingestor.get_aggregated_metrics()
print('[+] Aggregated metrics from real SQL query:')
print('    Total threats:', metrics['totalThreatsMonitored'])
print('    Verified malicious:', metrics['verifiedMaliciousDomains'])
print('    Active campaigns:', metrics['activeCampaigns24h'])
print('    Category breakdown:', metrics['categoryBreakdown'])
assert metrics['totalThreatsMonitored'] == len(all_threats)
assert metrics['verifiedMaliciousDomains'] > 0

# 5. Check provider transparency statuses
statuses = ingestor.get_providers_status()
print('[+] Provider transparency status:')
for s in statuses:
    print(f"    - {s['providerId']}: {s['status']} (Configured: {s['isConfigured']}, Last Error: {s['lastError']})")

# Verify unconfigured providers report NOT_CONFIGURED without fake data
urlhaus_status = next(s for s in statuses if s['providerId'] == 'urlhaus')
assert urlhaus_status['status'] == 'NOT_CONFIGURED'

# Cleanup test db
try:
    del ingestor
    if os.path.exists(db_path):
        os.remove(db_path)
except Exception:
    pass

print('\n[+] ALL INGESTOR CORE CHECKS PASSED SUCCESSFULLY!')
