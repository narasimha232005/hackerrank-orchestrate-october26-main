import pandas as pd
from collections import defaultdict

sa = pd.read_csv('dataset/system_activity.csv')
sa['dt'] = pd.to_datetime(sa['event_time'])
dw = sa[sa['source_system'] == 'deletion_worker']

reqs = pd.read_csv('dataset/deletion_requests.csv')

# Let's inspect case_83 to case_92
for cid in [f"case_{i}" for i in range(83, 93)]:
    r = reqs[reqs['case_id'] == cid].iloc[0]
    rep_dt = pd.to_datetime(r['reported_at'])
    events = dw[(dw['dt'] >= rep_dt - pd.Timedelta(hours=4)) & (dw['dt'] <= rep_dt + pd.Timedelta(hours=4))]
    print(f"{cid} ({r['email']}) at {r['reported_at']}:")
    for _, er in events.iterrows():
        print(f"   {er['target_system']} | {er['resource_id']} | {er['event_type']} | {er['reported_result']}")
