import pandas as pd
sa = pd.read_csv('dataset/system_activity.csv')
dw = sa[sa['source_system'] == 'deletion_worker']
print(f"Total deletion_worker events: {len(dw)}")
print(dw['event_type'].value_counts())
print("\nUnique reported results by event_type:")
for et, grp in dw.groupby('event_type'):
    print(f"  {et}: {grp['reported_result'].value_counts().to_dict()}")
