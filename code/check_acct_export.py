import json

with open('dataset/evidence/records/service_resource_export_20260915_114455.json', 'r') as f:
    d = json.load(f)

acct = d.get('service_exports', {}).get('account_service', {})
print("account_service keys:", list(acct.keys()))
for k, v in acct.items():
    print(k, len(v) if isinstance(v, list) else v)
    if isinstance(v, list):
        for item in v:
            print("  ", item)
