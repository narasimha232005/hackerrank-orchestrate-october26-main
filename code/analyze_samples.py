import pandas as pd
import json

df_samples = pd.read_csv('dataset/sample_deletion_requests.csv')
df_out = pd.read_csv('dataset/sample_output.csv')
merged = pd.merge(df_samples, df_out, on='case_id')
for idx, row in merged.iterrows():
    steps = json.loads(row['steps_json'])
    print(f"{row['case_id']} | {row['deletion_status']} | steps={len(steps)} | email={row['email']} | reported={row['reported_status']}")
    for s in steps:
        print(f"   [{s['phase']}] {s['system_id']} : {s['resource_id']} -> {s['operation']} ({s['state']}) ev={s['evidence_id']}")
