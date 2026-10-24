import json
import os
import re
import sqlite3
import pandas as pd
from collections import defaultdict

# Load metadata
users_df = pd.read_csv('dataset/user_identities.csv')
audit_df = pd.read_csv('dataset/user_audit_log.csv')
rules_df = pd.read_csv('dataset/deletion_rules.csv')
ef_df = pd.read_csv('dataset/evidence_files.csv').set_index('file_id')
ef_df['dt'] = pd.to_datetime(ef_df['captured_at'])
sa_df = pd.read_csv('dataset/system_activity.csv')
sa_df['dt'] = pd.to_datetime(sa_df['event_time'])

# Build identity maps
email_to_uid = {}
uid_to_emails = defaultdict(set)
uid_to_phones = defaultdict(set)
uid_to_names = defaultdict(set)
uid_to_hashes = defaultdict(set)

for _, r in users_df.iterrows():
    uid = r['user_id']
    em = str(r['email']).lower()
    email_to_uid[em] = uid
    uid_to_emails[uid].add(em)
    if pd.notna(r['name']): uid_to_names[uid].add(str(r['name']).lower())
    if pd.notna(r['phone']): uid_to_phones[uid].add(str(r['phone']))
    if pd.notna(r['email_hash']): uid_to_hashes[uid].add(str(r['email_hash']).lower())

for _, r in audit_df.iterrows():
    uid = r['user_id']
    fn = r['field_name']
    old_v = str(r['old_value']) if pd.notna(r['old_value']) else None
    new_v = str(r['new_value']) if pd.notna(r['new_value']) else None
    if fn == 'email':
        if old_v:
            email_to_uid[old_v.lower()] = uid
            uid_to_emails[uid].add(old_v.lower())
        if new_v:
            email_to_uid[new_v.lower()] = uid
            uid_to_emails[uid].add(new_v.lower())
    elif fn == 'phone':
        if old_v: uid_to_phones[uid].add(old_v)
        if new_v: uid_to_phones[uid].add(new_v)
    elif fn == 'name':
        if old_v: uid_to_names[uid].add(old_v.lower())
        if new_v: uid_to_names[uid].add(new_v.lower())

print("Identities loaded successfully.")
