import pandas as pd
sa = pd.read_csv('dataset/system_activity.csv')
print(sa.iloc[3425:3440][['activity_id', 'event_time', 'event_type', 'target_system', 'resource_id', 'reported_result', 'details']].to_string())
