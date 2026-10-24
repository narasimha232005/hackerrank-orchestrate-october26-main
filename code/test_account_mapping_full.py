import os
import json
import sqlite3
import pandas as pd
import re
from collections import defaultdict

data_dir = 'dataset'
ef = pd.read_csv('dataset/evidence_files.csv')
users = pd.read_csv('dataset/user_identities.csv')
audit = pd.read_csv('dataset/user_audit_log.csv')

e2u = {}
for _, r in users.iterrows():
    e2u[str(r['email']).lower()] = r['user_id']
for _, r in audit.iterrows():
    if r['field_name'] == 'email':
        if pd.notna(r['old_value']): e2u[str(r['old_value']).lower()] = r['user_id']
        if pd.notna(r['new_value']): e2u[str(r['new_value']).lower()] = r['user_id']

u2acct = {}

# 1. Snapshot bundles
for _, r in ef[ef['origin'] == 'records_assurance_snapshot_bundle'].iterrows():
    p = os.path.join(data_dir, r['file_path'])
    try:
        with open(p, 'r', encoding='utf-8') as f: d = json.load(f)
        for s in d.get('snapshots', []):
            for rec in s.get('records', []):
                rid = rec.get('resource_id', '')
                if 'account_' in rid:
                    sref = rec.get('customer_reference')
                    em = rec.get('email')
                    if sref: u2acct[sref] = rid
                    if em and str(em).lower() in e2u: u2acct[e2u[str(em).lower()]] = rid
    except Exception: pass

# 2. SRE profile lookups
for _, r in ef[ef['origin'] == 'service_resource_export'].iterrows():
    p = os.path.join(data_dir, r['file_path'])
    try:
        with open(p, 'r', encoding='utf-8') as f: d = json.load(f)
        lookups = d.get('service_exports', {}).get('account_service', {}).get('profile_lookups', [])
        for it in lookups:
            rid = it.get('resource_id')
            prof = it.get('profile') or {}
            em = prof.get('email')
            if rid and em and str(em).lower() in e2u: u2acct[e2u[str(em).lower()]] = rid
    except Exception: pass

# 3. SQL replicas
for _, r in ef[ef['file_path'].str.endswith('.sql')].iterrows():
    p = os.path.join(data_dir, r['file_path'])
    try:
        conn = sqlite3.connect(':memory:')
        with open(p, 'r', encoding='utf-8', errors='ignore') as f: conn.executescript(f.read())
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        for t in [t[0] for t in cur.fetchall()]:
            cur.execute(f"PRAGMA table_info({t})")
            cols = [c[1] for c in cur.fetchall()]
            if 'resource_id' in cols and 'email' in cols:
                cur.execute(f"SELECT resource_id, email, user_id FROM {t} WHERE resource_id LIKE 'account_%'")
                for rid, em, uid in cur.fetchall():
                    if uid: u2acct[uid] = rid
                    if em and str(em).lower() in e2u: u2acct[e2u[str(em).lower()]] = rid
            elif 'record_json' in cols:
                cur.execute(f"SELECT resource_id, record_json FROM {t} WHERE resource_id LIKE 'account_%'")
                for rid, rjson in cur.fetchall():
                    try:
                        jd = json.loads(rjson)
                        uid = jd.get('customer_reference') or jd.get('user_id')
                        em = jd.get('email')
                        if uid: u2acct[uid] = rid
                        if em and str(em).lower() in e2u: u2acct[e2u[str(em).lower()]] = rid
                    except Exception: pass
        conn.close()
    except Exception: pass

# 4. Text handover
handover_p = os.path.join(data_dir, 'evidence/records/customer_account_handover_20261001.txt')
if os.path.exists(handover_p):
    with open(handover_p, 'r', encoding='utf-8') as f:
        for line in f:
            m = re.search(r'(account_\d+).*?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})', line)
            if m:
                em = m.group(2).lower()
                if em in e2u: u2acct[e2u[em]] = m.group(1)

# 5. Logs
for _, r in ef[ef['file_path'].str.endswith('.log')].iterrows():
    p = os.path.join(data_dir, r['file_path'])
    try:
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if 'account_' in line:
                    m_acc = re.search(r'resource_id=(account_\d+)', line)
                    m_em = re.search(r'(?:lookup_key|correlation_key|match_key)="?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"?', line)
                    if m_acc and m_em:
                        em = m_em.group(1).lower()
                        if em in e2u: u2acct[e2u[em]] = m_acc.group(1)
    except Exception: pass

print(f"Total users mapped to account_XXXX: {len(u2acct)} / {len(users)}")
for u in ['user_26', 'user_27', 'user_28', 'user_29', 'user_30', 'user_541', 'user_542', 'user_12', 'user_15', 'user_17']:
    print(f"  {u} -> {u2acct.get(u)}")
