import sys
sys.stdout.reconfigure(encoding='utf-8')
import pandas as pd

df = pd.read_csv('dataset/deletion_requests.csv')

non_del_phrases = [
    'leave the account active', 'not asking for deletion', 'keep the account as it is',
    'do not close the account', 'without removing any of my records', 'marketing lists only',
    'not a request to erase', 'leave my profile and purchase history in place',
    'want to continue using the service', "don't delete or change anything",
    'opt-out', 'access request', 'download my account information', 'resetting the login'
]

potential_na = []
for idx, r in df.iterrows():
    t = r['request_text'].lower()
    for p in non_del_phrases:
        if p in t:
            potential_na.append((r['case_id'], p, r['request_text']))
            break

print(f"Total potential NOT_APPLICABLE found: {len(potential_na)}")
for c, p, t in potential_na:
    print(f"{c} [{p}]: {t}")
