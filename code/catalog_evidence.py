import os
import json
import sqlite3
import pandas as pd

ef = pd.read_csv('dataset/evidence_files.csv')
print(f"Total evidence files: {len(ef)}")

summary = []
for _, row in ef.iterrows():
    fid = row['file_id']
    fpath = os.path.join('dataset', row['file_path'])
    origin = row['origin']
    cap = row['captured_at']
    ext = os.path.splitext(fpath)[1].lower()
    size = os.path.getsize(fpath) if os.path.exists(fpath) else -1
    
    info = {'file_id': fid, 'path': row['file_path'], 'origin': origin, 'captured_at': cap, 'ext': ext, 'size': size}
    
    if ext == '.json' and os.path.exists(fpath):
        try:
            with open(fpath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict):
                info['keys'] = list(data.keys())
            elif isinstance(data, list):
                info['keys'] = f"list of {len(data)}"
        except Exception as e:
            info['keys'] = f"error: {e}"
            
    elif ext == '.sql' and os.path.exists(fpath):
        try:
            # Let's inspect create table statements
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            tables = [l.split()[2] for l in content.split('\n') if l.upper().startswith('CREATE TABLE')]
            info['tables'] = tables
        except Exception as e:
            info['tables'] = f"error: {e}"
            
    summary.append(info)

df_sum = pd.DataFrame(summary)
print(df_sum[['file_id', 'ext', 'size', 'origin']].to_string())
