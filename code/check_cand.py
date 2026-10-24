from solve_all import DeletionAuditor
import pandas as pd

a = DeletionAuditor()
reqs = pd.read_csv('dataset/sample_deletion_requests.csv').set_index('case_id')
for cid in ['case_03', 'case_09', 'case_12', 'case_15', 'case_17']:
    r = reqs.loc[cid]
    em = str(r['email']).lower()
    uid = a.e2u.get(em)
    audit_dt = pd.to_datetime(r['audit_at'])
    print(f"{cid}: uid={uid}, audit_at={r['audit_at']}")
    cand = a.ef[a.ef['dt'] <= audit_dt].sort_values('dt', ascending=False)
    for fid, row in cand.iloc[:3].iterrows():
        print(f"   {fid}: {row['origin']} ({row['captured_at']})")
