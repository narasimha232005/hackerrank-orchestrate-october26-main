from solve_all import DeletionAuditor
import pandas as pd
a = DeletionAuditor()
reqs = pd.read_csv('dataset/deletion_requests.csv')
r = reqs[reqs['case_id'] == 'case_33'].iloc[0]
em = str(r['email']).lower()
uid = a.e2u.get(em)
audit_dt = pd.to_datetime(r['audit_at'])
cand_ef = a.ef[a.ef['dt'] <= audit_dt].sort_values('dt', ascending=False)
print("uid:", uid, "em:", em, "audit_dt:", audit_dt)
print("Top 5 cand_ef:")
for fid, row in cand_ef.head(5).iterrows():
    print(fid, row['origin'], row['captured_at'])
