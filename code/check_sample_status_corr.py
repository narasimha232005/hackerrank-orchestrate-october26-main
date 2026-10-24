import pandas as pd

sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv').set_index('case_id')
sample_out = pd.read_csv('dataset/sample_output.csv').set_index('case_id')
df = sample_reqs.join(sample_out)
print(pd.crosstab(df['reported_status'], df['deletion_status']))
print("\nIndividual mapping:")
for cid, r in df.iterrows():
    print(f"{cid}: reported={r['reported_status']} -> actual={r['deletion_status']}")
