import pandas as pd
from datetime import datetime

df_req = pd.read_csv('dataset/deletion_requests.csv')
df_sample = pd.read_csv('dataset/sample_deletion_requests.csv')
ef = pd.read_csv('dataset/evidence_files.csv')

all_reqs = pd.concat([df_sample, df_req], ignore_index=True)

# Parse timestamps
ef['dt'] = pd.to_datetime(ef['captured_at'])
all_reqs['dt'] = pd.to_datetime(all_reqs['audit_at'])

print("Unique audit_at values:", all_reqs['dt'].nunique())

audit_times = sorted(all_reqs['dt'].unique())

for at in audit_times[:15]:
    # Find evidence files captured at or before at
    sub_ef = ef[ef['dt'] <= at].sort_values('dt', ascending=False)
    latest_ef = sub_ef.head(5)
    cases = all_reqs[all_reqs['dt'] == at]['case_id'].tolist()
    print(f"\nAudit_at: {at} ({len(cases)} cases: {cases[:5]}...)")
    for _, r in latest_ef.iterrows():
        print(f"   {r['file_id']} ({r['captured_at']}): {r['file_path']} [{r['origin']}]")
