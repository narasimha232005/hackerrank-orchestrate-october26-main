import json
with open('dataset/evidence/records/customer_data_snapshot_bundle_20260915.json', 'r') as f:
    d = json.load(f)

for s in d.get('snapshots', []):
    for rec in s.get('records', []):
        rid = rec.get('resource_id', '')
        if rid in ['tombstone_440', 'tombstone_9178']:
            print(json.dumps(rec, indent=2))
