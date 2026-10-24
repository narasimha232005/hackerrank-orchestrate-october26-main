import os
import json
import re
import sqlite3
import pandas as pd
from collections import defaultdict

users_df = pd.read_csv('dataset/user_identities.csv')
audit_df = pd.read_csv('dataset/user_audit_log.csv')
ef_df = pd.read_csv('dataset/evidence_files.csv')
sa_df = pd.read_csv('dataset/system_activity.csv')

# Build mapping from email -> user_id
email_to_uid = {}
for _, r in users_df.iterrows():
    email_to_uid[str(r['email']).lower()] = r['user_id']
for _, r in audit_df[audit_df['field_name'] == 'email'].iterrows():
    if pd.notna(r['old_value']): email_to_uid[str(r['old_value']).lower()] = r['user_id']
    if pd.notna(r['new_value']): email_to_uid[str(r['new_value']).lower()] = r['user_id']

user_to_account = {}

# 1. From data catalog in SA
for _, r in sa_df[sa_df['event_type'] == 'LINK_RESOURCE_IDENTITY'].iterrows():
    det = str(r['details'])
    m_uid = re.search(r'(user_\d+)', det)
    m_acc = re.search(r'(account_\d+)', det)
    if m_uid and m_acc:
        user_to_account[m_uid.group(1)] = m_acc.group(1)

# 2. From SQL databases (replicas and inventories)
for _, r in ef_df[ef_df['file_path'].str.endswith('.sql')].iterrows():
    p = 'dataset/' + r['file_path']
    try:
        conn = sqlite3.connect(':memory:')
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            conn.executescript(f.read())
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [t[0] for t in cur.fetchall()]
        for t in tables:
            if 'profile' in t or 'account' in t or 'replica' in t or 'primary' in t:
                cur.execute(f"PRAGMA table_info({t})")
                cols = [c[1] for c in cur.fetchall()]
                if 'resource_id' in cols and 'email' in cols:
                    cur.execute(f"SELECT resource_id, email FROM {t} WHERE resource_id LIKE 'account_%'")
                    for rid, em in cur.fetchall():
                        if em and str(em).lower() in email_to_uid:
                            user_to_account[email_to_uid[str(em).lower()]] = rid
        conn.close()
    except Exception as e:
        pass

# 3. From text / handover files
for _, r in ef_df[ef_df['file_path'].str.endswith('.txt')].iterrows():
    p = 'dataset/' + r['file_path']
    with open(p, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = re.search(r'(account_\d+).*?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})', line)
            if m:
                em = m.group(2).lower()
                if em in email_to_uid:
                    user_to_account[email_to_uid[em]] = m.group(1)

# 4. From log files
for _, r in ef_df[ef_df['file_path'].str.endswith('.log')].iterrows():
    p = 'dataset/' + r['file_path']
    with open(p, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if 'account_' in line:
                m_acc = re.search(r'resource_id=(account_\d+)', line)
                m_em = re.search(r'(?:lookup_key|correlation_key|match_key)="?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"?', line)
                if m_acc and m_em:
                    em = m_em.group(1).lower()
                    if em in email_to_uid:
                        user_to_account[email_to_uid[em]] = m_acc.group(1)

# 5. From JSON files
for _, r in ef_df[ef_df['file_path'].str.endswith('.json')].iterrows():
    p = 'dataset/' + r['file_path']
    try:
        with open(p, 'r', encoding='utf-8') as f:
            d = json.load(f)
        # check service_exports.account_service
        acc_lookups = d.get('service_exports', {}).get('account_service', {}).get('profile_lookups', [])
        for item in acc_lookups:
            rid = item.get('resource_id')
            # Look at profile if present
            prof = item.get('profile') or {}
            em = prof.get('email')
            if rid and em and str(em).lower() in email_to_uid:
                user_to_account[email_to_uid[str(em).lower()]] = rid
    except Exception:
        pass

print(f"Total user -> account mappings found: {len(user_to_account)}")
