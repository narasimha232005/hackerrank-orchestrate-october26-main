import pandas as pd

sa = pd.read_csv('dataset/system_activity.csv')
sa['dt'] = pd.to_datetime(sa['event_time'])
dw = sa[sa['source_system'] == 'deletion_worker']
dw_acct = dw[dw['target_system'] == 'account_service']

reqs = pd.read_csv('dataset/deletion_requests.csv')

for hrs in [1, 2, 3, 4, 6, 12]:
    matched = 0
    for _, r in reqs.iterrows():
        rep_dt = pd.to_datetime(r['reported_at'])
        cand = dw_acct[(dw_acct['dt'] >= rep_dt - pd.Timedelta(hours=hrs)) & (dw_acct['dt'] <= rep_dt + pd.Timedelta(hours=hrs))]
        if len(cand) > 0:
            matched += 1
    print(f"Hours {hrs}: matched {matched} / 518")
