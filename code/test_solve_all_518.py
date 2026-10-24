from solve_all import DeletionAuditor
import pandas as pd
import json

auditor = DeletionAuditor()
reqs = pd.read_csv('dataset/deletion_requests.csv')
print(f"Auditing {len(reqs)} cases...")

results = []
statuses = []
for idx, r in reqs.iterrows():
    res = auditor.audit_case(r)
    results.append(res)
    statuses.append(res['deletion_status'])

df = pd.DataFrame(results)
print("Done! Value counts of deletion_status:")
print(df['deletion_status'].value_counts())
print("\nSample predictions:")
print(df.head(10).to_string())
