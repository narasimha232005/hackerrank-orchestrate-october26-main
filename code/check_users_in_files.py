import pandas as pd
from solve_all import DeletionAuditor

a = DeletionAuditor()
reqs = pd.read_csv('dataset/sample_deletion_requests.csv').set_index('case_id')
files = ['evidence_01', 'evidence_51', 'evidence_92']
file_contents = {}
for fid in files:
    row = a.ef.loc[fid]
    with open('dataset/' + row['file_path'], 'r', encoding='utf-8', errors='ignore') as f:
        file_contents[fid] = f.read()

for cid in ['case_12', 'case_15', 'case_17', 'case_19', 'case_21', 'case_23', 'case_24', 'case_25', 'case_26', 'case_27', 'case_28', 'case_29', 'case_30', 'case_31', 'case_32']:
    r = reqs.loc[cid]
    em = str(r['email']).lower()
    uid = a.e2u.get(em)
    matches = []
    for fid in files:
        if uid in file_contents[fid] or em in file_contents[fid].lower():
            matches.append(fid)
    print(f"{cid} ({uid}, {em}): matches {matches}")
