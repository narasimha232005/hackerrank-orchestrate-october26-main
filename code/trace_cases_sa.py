import pandas as pd
import json

df_samples = pd.read_csv('dataset/sample_deletion_requests.csv')
sa = pd.read_csv('dataset/system_activity.csv')

for cid in ['case_21', 'case_22', 'case_23', 'case_24', 'case_25', 'case_26', 'case_27', 'case_28', 'case_29', 'case_30']:
    row = df_samples[df_samples['case_id'] == cid].iloc[0]
    em = row['email']
    req_t = row['requested_at']
    rep_t = row['reported_at']
    aud_t = row['audit_at']
    print(f"\n==========================================")
    print(f"{cid} | email={em} | req={req_t} | rep={rep_t} | aud={aud_t}")
    
    # Check all events in SA between req_t and aud_t that match email or resources
    # Let's see: what deletion_worker events occurred near rep_t?
    rep_dt = pd.to_datetime(rep_t)
    sa['dt'] = pd.to_datetime(sa['event_time'])
    nearby_sa = sa[(sa['dt'] >= rep_dt - pd.Timedelta(hours=4)) & (sa['dt'] <= rep_dt + pd.Timedelta(hours=4))]
    for _, s_row in nearby_sa.iterrows():
        if s_row['source_system'] == 'deletion_worker':
            print(f"  DW SA: {s_row['activity_id']} {s_row['event_time']} | {s_row['event_type']} {s_row['target_system']} {s_row['resource_id']} : {s_row['reported_result']}")
