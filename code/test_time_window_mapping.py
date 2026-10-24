import pandas as pd
from datetime import datetime

requests = pd.read_csv('dataset/deletion_requests.csv')
sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
all_reqs = pd.concat([sample_reqs, requests], ignore_index=True)

sa = pd.read_csv('dataset/system_activity.csv')
del_worker = sa[sa['source_system'] == 'deletion_worker'].copy()
del_worker['dt'] = pd.to_datetime(del_worker['event_time'])
all_reqs['req_dt'] = pd.to_datetime(all_reqs['requested_at'])
all_reqs['rep_dt'] = pd.to_datetime(all_reqs['reported_at'])

# Check for each request, what deletion_worker events occurred between req_dt and rep_dt (or rep_dt + 1 hour)
print(f"Total requests: {len(all_reqs)}")

mapped_cases = 0
for idx, r in all_reqs.iterrows():
    cid = r['case_id']
    req_t = r['req_dt']
    rep_t = r['rep_dt']
    
    # window between req_t and rep_t + 2 hours
    window_events = del_worker[(del_worker['dt'] >= req_t) & (del_worker['dt'] <= rep_t + pd.Timedelta(hours=2))]
    acct_events = window_events[window_events['target_system'] == 'account_service']
    if not acct_events.empty:
        mapped_cases += 1

print(f"Cases with account event in time window: {mapped_cases} / {len(all_reqs)}")
