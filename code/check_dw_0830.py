import pandas as pd
sa = pd.read_csv('dataset/system_activity.csv')
sa['dt'] = pd.to_datetime(sa['event_time'])
dw = sa[sa['source_system'] == 'deletion_worker']
print(dw[dw['event_time'].str.startswith('2026-08-30')][['activity_id', 'event_time', 'target_system', 'resource_id', 'reported_result', 'details']].to_string())
