import os
import pandas as pd

ef = pd.read_csv('dataset/evidence_files.csv')
logs = ef[ef['file_path'].str.endswith('.log') | ef['file_path'].str.endswith('.txt')]
print(f"Total log/txt files: {len(logs)}")
for _, r in logs.iterrows():
    p = os.path.join('dataset', r['file_path'])
    with open(p, 'r', encoding='utf-8', errors='ignore') as f:
        first_line = ""
        for line in f:
            if line.strip():
                first_line = line.strip()
                break
    print(f"{r['file_id']} ({r['origin']}): {first_line[:120]}")
