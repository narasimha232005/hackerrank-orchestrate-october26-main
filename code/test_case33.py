from solve_all import DeletionAuditor
import pandas as pd
a = DeletionAuditor()
reqs = pd.read_csv('dataset/deletion_requests.csv').set_index('case_id')
r = reqs.loc['case_33']
r['case_id'] = 'case_33'
print("Case 33:", a.audit_case(r))
