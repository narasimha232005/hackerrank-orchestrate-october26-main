import pandas as pd

sa = pd.read_csv('dataset/system_activity.csv')
sa['dt'] = pd.to_datetime(sa['event_time'])
dw = sa[sa['source_system'] == 'deletion_worker']
dw_acct = dw[dw['target_system'] == 'account_service']

reqs = pd.read_csv('dataset/deletion_requests.csv')
for _, r in reqs.iterrows():
    rep_dt = pd.to_datetime(r['reported_at'])
    cand = dw_acct[(dw_acct['dt'] >= rep_dt - pd.Timedelta(hours=24)) & (dw_acct['dt'] <= rep_dt + pd.Timedelta(hours=24))]
    if len(cand) == 0:
        print(r['case_id'], r['reported_at'], r['request_text'][:50])
