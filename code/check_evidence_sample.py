import pandas as pd
import json

df_samples = pd.read_csv('dataset/sample_deletion_requests.csv')
df_out = pd.read_csv('dataset/sample_output.csv')
merged = pd.merge(df_samples, df_out, on='case_id')

all_evids = set()
for idx, row in merged.iterrows():
    steps = json.loads(row['steps_json'])
    for s in steps:
        if s['evidence_id']:
            all_evids.add(s['evidence_id'])

print("Evidence IDs cited in sample_output.csv:", sorted(list(all_evids)))

ef = pd.read_csv('dataset/evidence_files.csv')
print("\nFiles corresponding to cited evidence IDs:")
print(ef[ef['file_id'].isin(all_evids)][['file_id', 'file_path', 'origin', 'captured_at']])
