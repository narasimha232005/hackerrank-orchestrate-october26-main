import json

with open('dataset/evidence/records/service_resource_export_20260915_114455.json', 'r') as f:
    d = json.load(f)

exports = d.get('service_exports', {})
for sys_name, res in exports.items():
    s = json.dumps(res)
    for rid in ['support_4715', 'analytics_4566', 'data_flow_6244', 'backup_3120']:
        if rid in s:
            print(f"{rid} is in {sys_name}:")
            for item in (res if isinstance(res, list) else [res]):
                if rid in json.dumps(item):
                    print("  ", item)
