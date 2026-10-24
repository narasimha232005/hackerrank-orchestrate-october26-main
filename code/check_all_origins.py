import pandas as pd
ef = pd.read_csv('dataset/evidence_files.csv')
print(ef['origin'].value_counts())
