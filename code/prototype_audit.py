import json
import os
import re
import sqlite3
import pandas as pd
from collections import defaultdict

# 1. Load reference datasets
users_df = pd.read_csv('dataset/user_identities.csv')
audit_df = pd.read_csv('dataset/user_audit_log.csv')
rules_df = pd.read_csv('dataset/deletion_rules.csv')
ef_df = pd.read_csv('dataset/evidence_files.csv').set_index('file_id')
ef_df['dt'] = pd.to_datetime(ef_df['captured_at'])
sa_df = pd.read_csv('dataset/system_activity.csv')

# User identity resolution
user_by_email = {}
emails_by_user = defaultdict(set)
phones_by_user = defaultdict(set)
names_by_user = defaultdict(set)
hashes_by_user = defaultdict(set)

for _, r in users_df.iterrows():
    uid = r['user_id']
    em = str(r['email']).lower()
    user_by_email[em] = uid
    emails_by_user[uid].add(em)
    if pd.notna(r['name']): names_by_user[uid].add(str(r['name']).lower())
    if pd.notna(r['phone']): phones_by_user[uid].add(str(r['phone']))
    if pd.notna(r['email_hash']): hashes_by_user[uid].add(str(r['email_hash']).lower())

for _, r in audit_df.iterrows():
    uid = r['user_id']
    fn = r['field_name']
    old_v = str(r['old_value']) if pd.notna(r['old_value']) else None
    new_v = str(r['new_value']) if pd.notna(r['new_value']) else None
    if fn == 'email':
        if old_v:
            user_by_email[old_v.lower()] = uid
            emails_by_user[uid].add(old_v.lower())
        if new_v:
            user_by_email[new_v.lower()] = uid
            emails_by_user[uid].add(new_v.lower())
    elif fn == 'phone':
        if old_v: phones_by_user[uid].add(old_v)
        if new_v: phones_by_user[uid].add(new_v)
    elif fn == 'name':
        if old_v: names_by_user[uid].add(old_v.lower())
        if new_v: names_by_user[uid].add(new_v.lower())

print(f"Loaded {len(users_df)} users, mapped {len(user_by_email)} emails.")
