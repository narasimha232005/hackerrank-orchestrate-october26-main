import pandas as pd
import json

df_samples = pd.read_csv('dataset/sample_deletion_requests.csv')
df_out = pd.read_csv('dataset/sample_output.csv')
merged = pd.merge(df_samples, df_out, on='case_id')
ef = pd.read_csv('dataset/evidence_files.csv').set_index('file_id')

for idx, r in merged.iterrows():
    steps = json.loads(r['steps_json'])
    evs = set(s['evidence_id'] for s in steps if s['evidence_id'])
    print(f"\n{r['case_id']}: audit_at={r['audit_at']} status={r['deletion_status']} email={r['email']}")
    for ev in evs:
        ev_row = ef.loc[ev]
        print(f"   Cited: {ev} -> {ev_row['file_path']} (cap={ev_row['captured_at']}, origin={ev_row['origin']})")
