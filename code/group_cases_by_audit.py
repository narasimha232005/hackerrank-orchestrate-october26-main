import pandas as pd
from collections import defaultdict

df_req = pd.read_csv('dataset/deletion_requests.csv')
ef = pd.read_csv('dataset/evidence_files.csv')
ef['dt'] = pd.to_datetime(ef['captured_at'])
df_req['dt'] = pd.to_datetime(df_req['audit_at'])

# Check for each request which evidence files are at or closest before audit_at
req_groups = defaultdict(list)
for _, r in df_req.iterrows():
    req_groups[r['audit_at']].append(r['case_id'])

print(f"Total audit_at groups: {len(req_groups)}")

# Map each audit_at to candidate evidence files
for at_str, cases in sorted(req_groups.items(), key=lambda x: x[0]):
    at_dt = pd.to_datetime(at_str)
    # files captured within 3 days before audit_at
    candidates = ef[(ef['dt'] <= at_dt) & (ef['dt'] >= at_dt - pd.Timedelta(days=2))].sort_values('dt', ascending=False)
    cand_info = [f"{r['file_id']} ({r['origin']})" for _, r in candidates.iterrows()]
    print(f"audit_at={at_str} | cases={len(cases)} (e.g. {cases[0]}) | candidates: {cand_info}")
