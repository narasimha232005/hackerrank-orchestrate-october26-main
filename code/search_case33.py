import os
import json
import pandas as pd

user_id = 'user_18'
email = 'ingrid.dahl@outlook.com'
phone = '+46 70 787 39 30'
ehash = '0649eddaba37af918d82b64da379e6623d34cf290b2a26ecbe53bafc1484f8af'

print("Searching system_activity.csv...")
sa = pd.read_csv('dataset/system_activity.csv')
for _, r in sa.iterrows():
    line = " ".join([str(v) for v in r.values])
    if user_id in line or email in line or phone in line:
        print(f"  SA: {r['activity_id']} {r['event_time']} {r['event_type']} {r['target_system']} {r['resource_id']} {r['reported_result']}")

print("\nSearching evidence files...")
ef = pd.read_csv('dataset/evidence_files.csv')
for _, r in ef.iterrows():
    fpath = os.path.join('dataset', r['file_path'])
    if not os.path.exists(fpath): continue
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as fp:
            content = fp.read()
        if user_id in content or email in content or phone in content or ehash in content:
            print(f"  Found in evidence: {r['file_id']} -> {r['file_path']} (cap={r['captured_at']}, origin={r['origin']})")
    except Exception as e:
        pass
