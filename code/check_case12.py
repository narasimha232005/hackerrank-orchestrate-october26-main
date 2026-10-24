from solve_all import DeletionAuditor
import pandas as pd
a = DeletionAuditor()
reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
r = reqs[reqs['case_id'] == 'case_12'].iloc[0]
res = a.audit_case(r)
print(res)
