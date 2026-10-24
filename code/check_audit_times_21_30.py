import pandas as pd
reqs = pd.read_csv('dataset/sample_deletion_requests.csv').set_index('case_id')
for cid in [f"case_{i:02d}" for i in range(21, 31)]:
    if cid in reqs.index:
        r = reqs.loc[cid]
        print(f"{cid}: rep_at={r['reported_at']}, audit_at={r['audit_at']}")
