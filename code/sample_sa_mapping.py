import pandas as pd
import json

df_samples = pd.read_csv('dataset/sample_deletion_requests.csv')
df_out = pd.read_csv('dataset/sample_output.csv')
merged = pd.merge(df_samples, df_out, on='case_id')
sa = pd.read_csv('dataset/system_activity.csv')

for idx, r in merged.iterrows():
    steps = json.loads(r['steps_json'])
    print(f"\n--- {r['case_id']} | req_at={r['requested_at']} | rep_at={r['reported_at']} | email={r['email']}")
    for s in steps:
        res_id = s['resource_id']
        sa_matches = sa[sa['resource_id'] == res_id]
        if not sa_matches.empty:
            for _, sa_row in sa_matches.iterrows():
                print(f"   Step res: {res_id} ({s['system_id']}) -> SA: {sa_row['activity_id']} | {sa_row['event_time']} | {sa_row['event_type']} | {sa_row['reported_result']} | {sa_row['details']}")
        else:
            print(f"   Step res: {res_id} ({s['system_id']}) -> NOT in system_activity")
