import json
import os
import re
import sqlite3
import pandas as pd
from collections import defaultdict
from evaluation.evaluator import evaluate_predictions

# 1. Identity Resolution
users_df = pd.read_csv('dataset/user_identities.csv')
audit_df = pd.read_csv('dataset/user_audit_log.csv')

email_to_uid = {}
uid_to_idents = defaultdict(lambda: {'emails': set(), 'phones': set(), 'names': set(), 'hashes': set()})

for _, r in users_df.iterrows():
    uid = r['user_id']
    em = str(r['email']).lower()
    email_to_uid[em] = uid
    uid_to_idents[uid]['emails'].add(em)
    if pd.notna(r['name']): uid_to_idents[uid]['names'].add(str(r['name']).lower())
    if pd.notna(r['phone']): uid_to_idents[uid]['phones'].add(str(r['phone']))
    if pd.notna(r['email_hash']): uid_to_idents[uid]['hashes'].add(str(r['email_hash']).lower())

for _, r in audit_df.iterrows():
    uid = r['user_id']
    fn = r['field_name']
    old_v = str(r['old_value']) if pd.notna(r['old_value']) else None
    new_v = str(r['new_value']) if pd.notna(r['new_value']) else None
    if fn == 'email':
        if old_v:
            email_to_uid[old_v.lower()] = uid
            uid_to_idents[uid]['emails'].add(old_v.lower())
        if new_v:
            email_to_uid[new_v.lower()] = uid
            uid_to_idents[uid]['emails'].add(new_v.lower())
    elif fn == 'phone':
        if old_v: uid_to_idents[uid]['phones'].add(old_v)
        if new_v: uid_to_idents[uid]['phones'].add(new_v)
    elif fn == 'name':
        if old_v: uid_to_idents[uid]['names'].add(old_v.lower())
        if new_v: uid_to_idents[uid]['names'].add(new_v.lower())

def match_val(val, uid):
    if not val or val == 'null' or val == 'None':
        return False
    v = str(val).strip().lower()
    if v == uid.lower():
        return True
    ids = uid_to_idents[uid]
    if v in ids['emails'] or v in ids['phones'] or v in ids['names'] or v in ids['hashes']:
        return True
    return False

# 2. System Activity & Data Catalog Indexing
sa_df = pd.read_csv('dataset/system_activity.csv')
sa_df['dt'] = pd.to_datetime(sa_df['event_time'])

data_catalog = {} # (uid or email, system_id) -> (resource_id, details)
user_audit_records = {} # uid -> audit_record_id
user_accounts = {} # uid -> account_id

for _, r in sa_df.iterrows():
    det = str(r['details'])
    rid = str(r['resource_id'])
    # Check data catalog links
    if r['event_type'] == 'LINK_RESOURCE_IDENTITY':
        for u in uid_to_idents:
            if u in det or any(e in det.lower() for e in uid_to_idents[u]['emails']):
                data_catalog[(u, r['target_system'])] = rid
                if 'audit_record' in rid:
                    user_audit_records[u] = rid
                if 'account' in rid:
                    user_accounts[u] = rid
                break
    elif r['source_system'] == 'deletion_worker':
        if r['target_system'] == 'account_service' and 'account_' in rid:
            # find which user this is near
            pass

print(f"Data catalog entries loaded: {len(data_catalog)}")
