import pandas as pd
import json

sample_out = pd.read_csv('dataset/sample_output.csv')
sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
users = pd.read_csv('dataset/user_identities.csv')
u_by_e = {r['email'].lower(): r['user_id'] for _, r in users.iterrows()}

for i in range(21, 31):
    cid = f'case_{i}'
    row = sample_reqs[sample_reqs['case_id'] == cid].iloc[0]
    gt_steps = json.loads(sample_out[sample_out['case_id'] == cid].iloc[0]['steps_json'])
    acct = [s['resource_id'] for s in gt_steps if s['system_id'] == 'account_service'][0]
    print(f"{cid} | {row['email']} | req={row['requested_at']} | rep={row['reported_at']} -> {acct}")
