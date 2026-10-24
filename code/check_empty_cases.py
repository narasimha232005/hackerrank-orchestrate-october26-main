import pandas as pd
import json
from solve_all import DeletionAuditor

a = DeletionAuditor()
reqs = pd.read_csv('dataset/deletion_requests.csv')
empty_cases = []
for _, r in reqs.iterrows():
    cid = r['case_id']
    res = a.audit_case(r)
    if res['steps_json'] == '[]' or res['steps_json'] == '':
        empty_cases.append((cid, res['deletion_status']))

print(f"Total empty steps cases: {len(empty_cases)}")
for c, st in empty_cases:
    print(c, st)
