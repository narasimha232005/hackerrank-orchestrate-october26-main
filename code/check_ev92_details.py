import json

with open('dataset/evidence/records/service_resource_export_20260915_114455.json', 'r') as f:
    d = json.load(f)

exports = d.get('service_exports', {})
print("Service export keys:", list(exports.keys()))
for sys_name, sys_val in exports.items():
    s = json.dumps(sys_val)
    for rid in ['account_3866', 'account_5482', 'account_7012', 'analytics_4574', 'analytics_5208']:
        if rid in s:
            print(f"{rid} found in {sys_name}")
