import json

with open('dataset/evidence/records/service_resource_export_20260915_114455.json', 'r', encoding='utf-8') as f:
    d = json.load(f)

targets = ['noah.f438085@outlook.com', 'user_29']

for sname, sdata in d['service_exports'].items():
    for subk, subv in sdata.items():
        if isinstance(subv, list):
            for item in subv:
                item_str = json.dumps(item)
                if any(t in item_str for t in targets):
                    print(f"Match in {sname} ({subk}): {item}")
