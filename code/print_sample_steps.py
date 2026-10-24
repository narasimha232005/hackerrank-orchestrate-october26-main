import pandas as pd
import json

df = pd.read_csv('dataset/sample_output.csv')
for cid in ['case_21', 'case_22', 'case_23', 'case_24', 'case_25', 'case_26', 'case_27', 'case_28', 'case_29', 'case_30']:
    r = df[df['case_id'] == cid].iloc[0]
    print(f"\n=== {cid} ({r['deletion_status']}) ===")
    steps = json.loads(r['steps_json'])
    for s in steps:
        print(f"  {s['phase']} | {s['system_id']} | {s['resource_id']} | {s['operation']} | {s['state']} | {s['evidence_id']}")
