import pandas as pd

sa = pd.read_csv('dataset/system_activity.csv')
sa['dt'] = pd.to_datetime(sa['event_time'])
dw = sa[sa['source_system'] == 'deletion_worker']
dw_acct = dw[dw['target_system'] == 'account_service']

reqs = pd.read_csv('dataset/deletion_requests.csv')
print(f"Total requests: {len(reqs)}")
print(f"Total dw account events: {len(dw_acct)}")

matched = 0
for _, r in reqs.iterrows():
    rep_dt = pd.to_datetime(r['reported_at'])
    # check if there's a dw account event within +/- 2 hours of reported_at
    cand = dw_acct[(dw_acct['dt'] >= rep_dt - pd.Timedelta(hours=2)) & (dw_acct['dt'] <= rep_dt + pd.Timedelta(hours=2))]
    if len(cand) > 0:
        matched += 1

print(f"Matched requests to dw account events: {matched} / {len(reqs)}")
