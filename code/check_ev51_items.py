with open('dataset/evidence/records/customer_data_snapshot_bundle_20260915.json', 'r') as f:
    s = f.read()
    for item in ['tombstone_440', 'tombstone_9178', 'account_4857', 'account_8858', 'account_3677', 'a.eze08', 'addo.kofi']:
        if item in s:
            print(f"{item} found in evidence_51")
