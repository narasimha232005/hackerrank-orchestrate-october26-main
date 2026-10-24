import pandas as pd

ef = pd.read_csv('dataset/evidence_files.csv')
for origin, group in ef.groupby('origin'):
    print(f"{origin} ({len(group)} files):")
    for _, row in group.iterrows():
        print(f"   {row['file_id']}: {row['file_path']} ({row['captured_at']})")
