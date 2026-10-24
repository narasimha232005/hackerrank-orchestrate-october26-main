import pandas as pd
reqs = pd.read_csv('dataset/deletion_requests.csv')
phrases = [
    'leave the account active', 'not asking for deletion', 'keep the account as it is',
    'do not close the account', 'without removing any of my records', 'marketing lists only',
    'not a request to erase', 'leave my profile and purchase history in place',
    'want to continue using the service', "don't delete or change anything",
    'download my account information', 'resetting the login'
]
matches = []
for _, r in reqs.iterrows():
    if any(p in str(r['request_text']).lower() for p in phrases):
        matches.append(r['case_id'])
print(f"Matches ({len(matches)}): {matches}")
