import pandas as pd
reqs = pd.read_csv('dataset/deletion_requests.csv')
r_0906 = reqs[reqs['reported_at'].str.startswith('2026-09-06')]
print(f"Total requests on 2026-09-06: {len(r_0906)}")
print(r_0906[['case_id', 'email', 'reported_at', 'audit_at', 'request_text']])
