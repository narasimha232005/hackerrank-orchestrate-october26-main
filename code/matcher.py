import json
import os
import sqlite3
import pandas as pd
from collections import defaultdict

users_df = pd.read_csv('dataset/user_identities.csv')
audit_df = pd.read_csv('dataset/user_audit_log.csv')

# Build mapping from email -> user_id, and user_id -> identifiers
email_to_uid = {}
uid_to_identifiers = defaultdict(lambda: {'emails': set(), 'phones': set(), 'names': set(), 'hashes': set()})

for _, r in users_df.iterrows():
    uid = r['user_id']
    em = str(r['email']).lower()
    email_to_uid[em] = uid
    uid_to_identifiers[uid]['emails'].add(em)
    if pd.notna(r['name']): uid_to_identifiers[uid]['names'].add(str(r['name']).lower())
    if pd.notna(r['phone']): uid_to_identifiers[uid]['phones'].add(str(r['phone']))
    if pd.notna(r['email_hash']): uid_to_identifiers[uid]['hashes'].add(str(r['email_hash']).lower())

for _, r in audit_df.iterrows():
    uid = r['user_id']
    fn = r['field_name']
    old_v = str(r['old_value']) if pd.notna(r['old_value']) else None
    new_v = str(r['new_value']) if pd.notna(r['new_value']) else None
    if fn == 'email':
        if old_v:
            email_to_uid[old_v.lower()] = uid
            uid_to_identifiers[uid]['emails'].add(old_v.lower())
        if new_v:
            email_to_uid[new_v.lower()] = uid
            uid_to_identifiers[uid]['emails'].add(new_v.lower())
    elif fn == 'phone':
        if old_v: uid_to_identifiers[uid]['phones'].add(old_v)
        if new_v: uid_to_identifiers[uid]['phones'].add(new_v)
    elif fn == 'name':
        if old_v: uid_to_identifiers[uid]['names'].add(old_v.lower())
        if new_v: uid_to_identifiers[uid]['names'].add(new_v.lower())

def match_user(val, uid):
    if not val or val == 'null' or val == 'None':
        return False
    v = str(val).strip().lower()
    if v == uid.lower():
        return True
    ids = uid_to_identifiers[uid]
    if v in ids['emails']:
        return True
    if v in ids['phones']:
        return True
    if v in ids['names']:
        return True
    if v in ids['hashes']:
        return True
    return False

print("Matcher test ready.")
