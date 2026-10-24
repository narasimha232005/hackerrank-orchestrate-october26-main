import pandas as pd
import json

sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
eval_reqs = pd.read_csv('dataset/deletion_requests.csv')
all_reqs = pd.concat([sample_reqs, eval_reqs], ignore_index=True)
all_reqs['req_dt'] = pd.to_datetime(all_reqs['requested_at'])
all_reqs['rep_dt'] = pd.to_datetime(all_reqs['reported_at'])

sa = pd.read_csv('dataset/system_activity.csv')
dw = sa[sa['source_system'] == 'deletion_worker'].copy()
dw['dt'] = pd.to_datetime(dw['event_time'])

# Group requests by reported_at
for rep_t, req_group in all_reqs.groupby('reported_at'):
    rep_dt = pd.to_datetime(rep_t)
    sub_dw = dw[(dw['dt'] >= rep_dt - pd.Timedelta(hours=4)) & (dw['dt'] <= rep_dt + pd.Timedelta(hours=3))]
    acct_dw = sub_dw[sub_dw['target_system'] == 'account_service']
    if len(req_group) > 1 and len(acct_dw) > 0:
        print(f"\nRep_at: {rep_t} | {len(req_group)} requests vs {len(acct_dw)} account events")
        for _, r in req_group.iterrows():
            print(f"   Req: {r['case_id']} | req_at={r['requested_at']} | email={r['email']}")
        for _, a in acct_dw.iterrows():
            print(f"   DW Acct: {a['activity_id']} | time={a['event_time']} | res={a['resource_id']} | result={a['reported_result']}")
