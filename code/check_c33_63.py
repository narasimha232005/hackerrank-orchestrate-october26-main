import pandas as pd
reqs = pd.read_csv('dataset/deletion_requests.csv')
c33_63 = reqs[(reqs['case_id'] >= 'case_33') & (reqs['case_id'] <= 'case_63')]
print(f"Total single-file cases: {len(c33_63)}")
print(c33_63[['case_id', 'email', 'reported_at', 'audit_at', 'reported_status']].head(15).to_string())
