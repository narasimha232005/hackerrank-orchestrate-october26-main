import pandas as pd
df = pd.read_csv('dataset/deletion_requests.csv')
emails = ['rafael.r9464@outlook.com', 'ishaan.iyer@outlook.com', 'JULES-LAURENT@PROTON.ME', 'aoi-yamamoto@gmail.com', 'ajohansson9059@fastmail.com']
for e in emails:
    row = df[df['email'].str.lower() == e.lower()]
    if not row.empty:
        r = row.iloc[0]
        print(f"{r['case_id']}: {r['email']}, audit_at={r['audit_at']}")
