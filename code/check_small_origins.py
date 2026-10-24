import pandas as pd
ef = pd.read_csv('dataset/evidence_files.csv')
counts = ef['origin'].value_counts()
small_origins = counts[counts <= 3].index
print(ef[ef['origin'].isin(small_origins)][['file_id', 'origin', 'file_path', 'captured_at']].to_string())
