import pandas as pd
sa = pd.read_csv('dataset/system_activity.csv')
links = sa[sa['event_type'] == 'LINK_RESOURCE_IDENTITY']
for _, r in links.iterrows():
    print(f"{r['target_system']} | {r['resource_id']} | {r['details']}")
