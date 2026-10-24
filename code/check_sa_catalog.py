import pandas as pd
sa = pd.read_csv('dataset/system_activity.csv')
print(sa.iloc[3995:4015][['activity_id', 'event_type', 'target_system', 'resource_id', 'details']].to_string())
