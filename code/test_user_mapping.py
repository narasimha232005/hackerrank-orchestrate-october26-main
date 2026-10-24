import os
import json
import sqlite3
import pandas as pd
from collections import defaultdict

# Load identities and audit logs
users = pd.read_csv('dataset/user_identities.csv')
audit = pd.read_csv('dataset/user_audit_log.csv')
requests = pd.read_csv('dataset/deletion_requests.csv')
ef = pd.read_csv('dataset/evidence_files.csv')

# Build user lookup maps:
# email -> user_id, phone, email_hash, all historical emails, all historical phones
user_by_email = {}
all_emails_by_user = defaultdict(set)
all_phones_by_user = defaultdict(set)

for _, row in users.iterrows():
    uid = row['user_id']
    email = row['email']
    phone = str(row['phone']) if pd.notna(row['phone']) else None
    ehash = row['email_hash']
    
    all_emails_by_user[uid].add(email)
    if phone:
        all_phones_by_user[uid].add(phone)
    user_by_email[email] = uid

for _, row in audit.iterrows():
    uid = row['user_id']
    fname = row['field_name']
    old_val = row['old_value']
    new_val = row['new_value']
    if fname == 'email':
        if pd.notna(old_val):
            all_emails_by_user[uid].add(old_val)
            user_by_email[old_val] = uid
        if pd.notna(new_val):
            all_emails_by_user[uid].add(new_val)
            user_by_email[new_val] = uid
    elif fname == 'phone':
        if pd.notna(old_val):
            all_phones_by_user[uid].add(old_val)
        if pd.notna(new_val):
            all_phones_by_user[uid].add(new_val)

print(f"Total users in identities: {len(users)}")
print(f"Total mapped emails: {len(user_by_email)}")

# Check how many requests map to user_id
unmapped_requests = []
req_user_map = {}
for _, row in requests.iterrows():
    cid = row['case_id']
    em = row['email']
    if em in user_by_email:
        req_user_map[cid] = user_by_email[em]
    else:
        unmapped_requests.append((cid, em))

print(f"Mapped requests: {len(req_user_map)} / {len(requests)}")
if unmapped_requests:
    print(f"Unmapped sample: {unmapped_requests[:5]}")
