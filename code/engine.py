import json
import os
import re
import sqlite3
import pandas as pd
from collections import defaultdict
from evaluation.evaluator import evaluate_predictions

class DeletionAuditEngine:
    def __init__(self, dataset_dir='dataset'):
        self.dataset_dir = dataset_dir
        self._load_metadata()
        self._load_evidence_data()

    def _load_metadata(self):
        # 1. Users and Audit
        self.users_df = pd.read_csv(os.path.join(self.dataset_dir, 'user_identities.csv'))
        self.audit_df = pd.read_csv(os.path.join(self.dataset_dir, 'user_audit_log.csv'))
        self.rules_df = pd.read_csv(os.path.join(self.dataset_dir, 'deletion_rules.csv'))
        self.ef_df = pd.read_csv(os.path.join(self.dataset_dir, 'evidence_files.csv')).set_index('file_id')
        self.ef_df['dt'] = pd.to_datetime(self.ef_df['captured_at'])
        self.sa_df = pd.read_csv(os.path.join(self.dataset_dir, 'system_activity.csv'))
        self.sa_df['dt'] = pd.to_datetime(self.sa_df['event_time'])

        self.email_to_uid = {}
        self.uid_to_idents = defaultdict(lambda: {'emails': set(), 'phones': set(), 'names': set(), 'hashes': set()})

        for _, r in self.users_df.iterrows():
            uid = r['user_id']
            em = str(r['email']).lower()
            self.email_to_uid[em] = uid
            self.uid_to_idents[uid]['emails'].add(em)
            if pd.notna(r['name']): self.uid_to_idents[uid]['names'].add(str(r['name']).lower())
            if pd.notna(r['phone']): self.uid_to_idents[uid]['phones'].add(str(r['phone']))
            if pd.notna(r['email_hash']): self.uid_to_idents[uid]['hashes'].add(str(r['email_hash']).lower())

        for _, r in self.audit_df.iterrows():
            uid = r['user_id']
            fn = r['field_name']
            old_v = str(r['old_value']) if pd.notna(r['old_value']) else None
            new_v = str(r['new_value']) if pd.notna(r['new_value']) else None
            if fn == 'email':
                if old_v:
                    self.email_to_uid[old_v.lower()] = uid
                    self.uid_to_idents[uid]['emails'].add(old_v.lower())
                if new_v:
                    self.email_to_uid[new_v.lower()] = uid
                    self.uid_to_idents[uid]['emails'].add(new_v.lower())
            elif fn == 'phone':
                if old_v: self.uid_to_idents[uid]['phones'].add(old_v)
                if new_v: self.uid_to_idents[uid]['phones'].add(new_v)
            elif fn == 'name':
                if old_v: self.uid_to_idents[uid]['names'].add(old_v.lower())
                if new_v: self.uid_to_idents[uid]['names'].add(new_v.lower())

        # 2. Map Security Audit Records
        self.user_to_audit_rec = {}
        # From SA catalog
        for _, r in self.sa_df.iterrows():
            rid = str(r['resource_id'])
            if 'audit_record' in rid:
                m = re.search(r'(user_\d+)', str(r['details']))
                if m: self.user_to_audit_rec[m.group(1)] = rid

        # From snapshot bundles
        for _, r in self.ef_df[self.ef_df['origin'] == 'records_assurance_snapshot_bundle'].iterrows():
            p = os.path.join(self.dataset_dir, r['file_path'])
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    d = json.load(f)
                for s in d.get('snapshots', []):
                    for rec in s.get('records', []):
                        rid = rec.get('resource_id', '')
                        sref = rec.get('subject_reference')
                        if 'audit_record' in rid and sref:
                            self.user_to_audit_rec[sref] = rid
            except Exception:
                pass

        # From service_resource_export
        for _, r in self.ef_df[self.ef_df['origin'] == 'service_resource_export'].iterrows():
            p = os.path.join(self.dataset_dir, r['file_path'])
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    d = json.load(f)
                for rec in d.get('service_exports', {}).get('security_service', {}).get('audit_records', []):
                    rid = rec.get('resource_id', '')
                    sref = rec.get('subject_reference')
                    if rid and sref:
                        self.user_to_audit_rec[sref] = rid
            except Exception:
                pass

        # From inventory sql
        for _, r in self.ef_df[self.ef_df['origin'] == 'customer_data_inventory_capture'].iterrows():
            p = os.path.join(self.dataset_dir, r['file_path'])
            try:
                conn = sqlite3.connect(':memory:')
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    conn.executescript(f.read())
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_audit_records'")
                if cur.fetchone():
                    cur.execute("SELECT resource_id, subject_reference FROM security_audit_records")
                    for rid, sref in cur.fetchall():
                        if rid and sref:
                            self.user_to_audit_rec[sref] = rid
                conn.close()
            except Exception:
                pass

        # From logs
        for _, r in self.ef_df[self.ef_df['file_path'].str.endswith('.log') | self.ef_df['file_path'].str.endswith('.txt')].iterrows():
            p = os.path.join(self.dataset_dir, r['file_path'])
            try:
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if 'audit_record' in line:
                            m1 = re.search(r'resource_id=(audit_record_\d+)', line)
                            m2 = re.search(r'(?:subject_reference|subject_ref|lookup_key)=(user_\d+)', line)
                            if m1 and m2:
                                self.user_to_audit_rec[m2.group(1)] = m1.group(1)
                            m3 = re.search(r'(?:subject_reference|subject_ref|lookup_key)=(user_\d+).*?resource_id=(audit_record_\d+)', line)
                            if m3:
                                self.user_to_audit_rec[m3.group(1)] = m3.group(2)
                            m4 = re.search(r'\|\s*security_service\s*\|\s*(audit_record_\d+)\s*\|\s*SECURITY_AUDIT_LOG\s*\|\s*FOUND\s*\|\s*(user_\d+)', line)
                            if m4:
                                self.user_to_audit_rec[m4.group(2)] = m4.group(1)
            except Exception:
                pass

        # 3. Data Catalog Links from SA
        self.catalog_links = {}
        for _, r in self.sa_df[self.sa_df['event_type'] == 'LINK_RESOURCE_IDENTITY'].iterrows():
            det = str(r['details'])
            rid = str(r['resource_id'])
            for u in self.uid_to_idents:
                if u in det or any(e in det.lower() for e in self.uid_to_idents[u]['emails']):
                    self.catalog_links[(u, r['target_system'])] = (rid, r['source_system'], r['details'])

    def _load_evidence_data(self):
        # We can index evidence by file_id
        pass

    def match_user(self, val, uid):
        if not val or val == 'null' or val == 'None':
            return False
        v = str(val).strip().lower()
        if v == uid.lower():
            return True
        ids = self.uid_to_idents[uid]
        if v in ids['emails'] or v in ids['phones'] or v in ids['names'] or v in ids['hashes']:
            return True
        return False

print("Engine base defined.")
