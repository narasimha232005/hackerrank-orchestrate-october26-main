import sys
sys.stdout.reconfigure(encoding='utf-8')
import pandas as pd
df = pd.read_csv('dataset/deletion_requests.csv')
for idx, r in df.iloc[495:].iterrows():
    print(f"{r['case_id']} | rep={r['reported_status']} | text={r['request_text']}")
