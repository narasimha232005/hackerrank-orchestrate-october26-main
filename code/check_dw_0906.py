import pandas as pd
sa = pd.read_csv('dataset/system_activity.csv')
dw = sa[sa['source_system'] == 'deletion_worker']
print(dw[dw['event_time'].str.startswith('2026-09-06')][['activity_id', 'event_time', 'target_system', 'resource_id', 'reported_result', 'details']].to_string())
