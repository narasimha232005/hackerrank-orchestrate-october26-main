import pandas as pd
from datetime import datetime
import json

sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
sa = pd.read_csv('dataset/system_activity.csv')
dw = sa[sa['source_system'] == 'deletion_worker'].copy()
dw['dt'] = pd.to_datetime(dw['event_time'])

sample_reqs['rep_dt'] = pd.to_datetime(sample_reqs['reported_at'])
sample_out = pd.read_csv('dataset/sample_output.csv')

for idx, r in sample_reqs.iterrows():
    cid = r['case_id']
    gt_row = sample_out[sample_out['case_id'] == cid].iloc[0]
    gt_steps = json.loads(gt_row['steps_json'])
    gt_resources = set(s['resource_id'] for s in gt_steps)
    
    # window
    rep_t = r['rep_dt']
    window_dw = dw[(dw['dt'] >= rep_t - pd.Timedelta(hours=4)) & (dw['dt'] <= rep_t + pd.Timedelta(hours=3))]
    matching_in_dw = set(window_dw['resource_id']).intersection(gt_resources)
    
    print(f"{cid} ({r['reported_status']}) | rep={r['reported_at']} | GT res: {sorted(list(gt_resources))}")
    print(f"   Matched in DW window: {sorted(list(matching_in_dw))}")
    missing = gt_resources - matching_in_dw
    if missing:
        print(f"   Missing from DW window: {sorted(list(missing))}")
