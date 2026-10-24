import sys
sys.stdout.reconfigure(encoding='utf-8')
import pandas as pd
import json

df_samples = pd.read_csv('dataset/sample_deletion_requests.csv')
df_out = pd.read_csv('dataset/sample_output.csv')
merged = pd.merge(df_samples, df_out, on='case_id')

for idx, r in merged.iterrows():
    steps = json.loads(r['steps_json'])
    print(f"=== {r['case_id']}: status={r['deletion_status']}, reported={r['reported_status']}, email={r['email']}, audit_at={r['audit_at']} ===")
    print(f"Request: {r['request_text'][:80]}...")
    for s in steps:
        print(f"  Step {s['step_no']}: [{s['phase']}] {s['system_id']} / {s['resource_id']} | op={s['operation']} | st={s['state']} | ev={s['evidence_id']}")
