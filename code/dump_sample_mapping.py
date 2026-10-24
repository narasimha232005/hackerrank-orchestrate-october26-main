import pandas as pd
import json

sample_out = pd.read_csv('dataset/sample_output.csv')
sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
merged = pd.merge(sample_reqs, sample_out, on='case_id')

for _, r in merged.iterrows():
    cid = r['case_id']
    steps = json.loads(r['steps_json'])
    evids = sorted(list(set(s['evidence_id'] for s in steps if s['evidence_id'])))
    resources = [(s['phase'], s['system_id'], s['resource_id'], s['operation'], s['state'], s['evidence_id']) for s in steps]
    print(f"{cid} ({r['deletion_status']}) | audit_at={r['audit_at']} | evids={evids}")
    for res in resources:
        print(f"   {res[0]} : {res[1]} / {res[2]} -> {res[3]} ({res[4]}) ev={res[5]}")
