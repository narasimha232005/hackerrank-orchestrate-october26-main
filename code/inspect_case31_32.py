import pandas as pd
reqs = pd.read_csv('dataset/sample_deletion_requests.csv').set_index('case_id')
for cid in ['case_31', 'case_32']:
    r = reqs.loc[cid]
    print(f"{cid}: rep_at={r['reported_at']}, audit_at={r['audit_at']}")
