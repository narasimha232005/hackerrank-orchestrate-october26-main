import os
import json
import re
import sqlite3
import pandas as pd
from collections import defaultdict

ef = pd.read_csv('dataset/evidence_files.csv')
user_audit_map = {}

# 1. Check snapshot bundles
bundles = ef[ef['origin'] == 'records_assurance_snapshot_bundle']
for _, r in bundles.iterrows():
    p = 'dataset/' + r['file_path']
    with open(p, 'r', encoding='utf-8') as f:
        d = json.load(f)
    for s in d.get('snapshots', []):
        for rec in s.get('records', []):
            rid = rec.get('resource_id', '')
            sref = rec.get('subject_reference')
            if 'audit_record' in rid and sref:
                user_audit_map[sref] = rid

# 2. Check service_resource_export
sre = ef[ef['origin'] == 'service_resource_export']
for _, r in sre.iterrows():
    p = 'dataset/' + r['file_path']
    with open(p, 'r', encoding='utf-8') as f:
        d = json.load(f)
    sec = d.get('service_exports', {}).get('security_service', {}).get('audit_records', [])
    for rec in sec:
        rid = rec.get('resource_id', '')
        sref = rec.get('subject_reference')
        if rid and sref:
            user_audit_map[sref] = rid

# 3. Check customer_data_inventory sql
inv = ef[ef['origin'] == 'customer_data_inventory_capture']
for _, r in inv.iterrows():
    p = 'dataset/' + r['file_path']
    conn = sqlite3.connect(':memory:')
    with open(p, 'r', encoding='utf-8', errors='ignore') as f:
        conn.executescript(f.read())
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_audit_records'")
    if cur.fetchone():
        cur.execute("SELECT resource_id, subject_reference FROM security_audit_records")
        for rid, sref in cur.fetchall():
            if rid and sref:
                user_audit_map[sref] = rid
    conn.close()

# 4. Check evidence_50 (security_audit_ledger_20261001.json)
if os.path.exists('dataset/evidence/records/security_audit_ledger_20261001.json'):
    with open('dataset/evidence/records/security_audit_ledger_20261001.json', 'r', encoding='utf-8') as f:
        d = json.load(f)
    for rec in d.get('audit_ledger_entries', []):
        rid = rec.get('resource_id', '')
        sref = rec.get('subject_reference')
        if rid and sref:
            user_audit_map[sref] = rid

# 5. Check log files (readback logs and observability logs)
logs = ef[ef['file_path'].str.endswith('.log') | ef['file_path'].str.endswith('.txt')]
for _, r in logs.iterrows():
    p = 'dataset/' + r['file_path']
    with open(p, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if 'audit_record' in line:
                # patterns: resource_id=(audit_record_\d+) ... (?:subject_reference|subject_ref|lookup_key)=(user_\d+)
                m1 = re.search(r'resource_id=(audit_record_\d+)', line)
                m2 = re.search(r'(?:subject_reference|subject_ref|lookup_key)=(user_\d+)', line)
                if m1 and m2:
                    user_audit_map[m2.group(1)] = m1.group(1)
                m3 = re.search(r'(?:subject_reference|subject_ref|lookup_key)=(user_\d+).*?resource_id=(audit_record_\d+)', line)
                if m3:
                    user_audit_map[m3.group(1)] = m3.group(2)
                # handover format: | security_service | audit_record_2019 | SECURITY_AUDIT_LOG | FOUND | user_35
                m4 = re.search(r'\|\s*security_service\s*\|\s*(audit_record_\d+)\s*\|\s*SECURITY_AUDIT_LOG\s*\|\s*FOUND\s*\|\s*(user_\d+)', line)
                if m4:
                    user_audit_map[m4.group(2)] = m4.group(1)

# 6. Check system_activity.csv data catalog links
sa = pd.read_csv('dataset/system_activity.csv')
for _, r in sa.iterrows():
    if 'audit_record' in str(r['resource_id']):
        m = re.search(r'(user_\d+)', str(r['details']))
        if m:
            user_audit_map[m.group(1)] = r['resource_id']

print(f"Total user -> audit_record mappings discovered: {len(user_audit_map)}")
