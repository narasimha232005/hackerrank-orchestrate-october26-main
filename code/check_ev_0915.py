import pandas as pd
ef = pd.read_csv('dataset/evidence_files.csv')
print(ef[ef['captured_at'].str.startswith('2026-09-15')][['file_id', 'origin', 'file_path', 'captured_at']])
