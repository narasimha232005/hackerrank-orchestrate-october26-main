import pandas as pd
from main import DeletionAuditEngine

engine = DeletionAuditEngine('dataset')
sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv').set_index('case_id')
r = sample_reqs.loc['case_06']
r['case_id'] = 'case_06'
uid = engine.email_to_uid.get(r['email'].lower())
print("case_06 uid:", uid, "email:", r['email'])
audit_dt = pd.to_datetime(r['audit_at'])
cand_ef = engine.ef_df[engine.ef_df['dt'] <= audit_dt].sort_values('dt', ascending=False)
for fid, row in cand_ef.head(5).iterrows():
    print(fid, row['origin'], row['file_path'])
