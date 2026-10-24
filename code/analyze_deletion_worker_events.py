import pandas as pd

sa = pd.read_csv('dataset/system_activity.csv')
del_worker = sa[sa['source_system'] == 'deletion_worker']
print(f"Total deletion worker events: {len(del_worker)}")
print("Event types from deletion_worker:")
print(del_worker['event_type'].value_counts())
print("\nTarget systems for deletion_worker:")
print(del_worker['target_system'].value_counts())
print("\nSample deletion_worker events:")
print(del_worker.head(20)[['activity_id', 'event_time', 'event_type', 'target_system', 'resource_id', 'reported_result', 'details']])
