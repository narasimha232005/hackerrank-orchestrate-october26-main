import pandas as pd
import json

sample_out = pd.read_csv('dataset/sample_output.csv')
sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
users = pd.read_csv('dataset/user_identities.csv')
audit = pd.read_csv('dataset/user_audit_log.csv')

u_by_e = {r['email'].lower(): r['user_id'] for _, r in users.iterrows()}
for _, r in audit[audit['field_name'] == 'email'].iterrows():
    if pd.notna(r['old_value']): u_by_e[r['old_value'].lower()] = r['user_id']
    if pd.notna(r['new_value']): u_by_e[r['new_value'].lower()] = r['user_id']

for _, r in sample_reqs.iterrows():
    cid = r['case_id']
    em = r['email'].lower()
    uid = u_by_e[em]
    gt_steps = json.loads(sample_out[sample_out['case_id'] == cid].iloc[0]['steps_json'])
    acct = [s['resource_id'] for s in gt_steps if s['system_id'] == 'account_service']
    print(f"{cid} | {uid} | {em} -> acct: {acct}")
