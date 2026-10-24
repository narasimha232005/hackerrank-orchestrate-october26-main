import json
import pandas as pd

ef = pd.read_csv('dataset/evidence_files.csv')
sre_files = ef[ef['origin'] == 'service_resource_export']

for _, r in sre_files.iterrows():
    p = 'dataset/' + r['file_path']
    with open(p, 'r', encoding='utf-8') as f:
        d = json.load(f)
    print(f"{r['file_id']} ({r['captured_at']}): services={list(d['service_exports'].keys())}")
