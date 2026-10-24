import pandas as pd

sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv').set_index('case_id')
ef = pd.read_csv('dataset/evidence_files.csv').set_index('file_id')

for cid in ['case_06', 'case_07', 'case_08', 'case_09', 'case_10']:
    r = sample_reqs.loc[cid]
    print(f"{cid}: rep_at={r['reported_at']}, audit_at={r['audit_at']}")
    # check closest evidence files
    cand = ef[ef['captured_at'] <= r['audit_at']].sort_values('captured_at', ascending=False)
    for fid, row in cand.head(3).iterrows():
        print(f"   {fid} ({row['origin']}): {row['captured_at']}")
