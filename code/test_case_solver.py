import json
import os
import re
import sqlite3
import pandas as pd
from collections import defaultdict
from evaluation.evaluator import evaluate_predictions

phase_order = {'FINDING': 1, 'REMEDIATION': 2, 'VERIFICATION': 3}
finding_ops = ['REPORT_REMAINING_RECORD', 'REPORT_EXPOSED_PII', 'REPORT_ACTIVE_DATA_FLOW', 'REPORT_RESTORE_RISK']
remed_ops = ['DISABLE_DATA_FLOW', 'BLOCK_RESTORE', 'DELETE_RECORD', 'REDACT_RECORD', 'ANONYMIZE_RECORD']
verif_ops = ['VERIFY_RECORD_ABSENT', 'VERIFY_RECORD_PRESENT', 'VERIFY_RECORD_REDACTED', 'VERIFY_RECORD_ANONYMIZED', 'VERIFY_DATA_FLOW_DISABLED', 'VERIFY_RESTORE_BLOCKED']
all_ops = finding_ops + remed_ops + verif_ops
op_order = {op: i for i, op in enumerate(all_ops)}

def sort_and_number_steps(steps):
    def sort_key(s):
        return (phase_order[s['phase']], op_order[s['operation']], s['system_id'], s['resource_id'])
    sorted_steps = sorted(steps, key=sort_key)
    for i, s in enumerate(sorted_steps):
        s['step_no'] = i + 1
    return sorted_steps

class AuditSolver:
    def __init__(self, data_dir='dataset'):
        self.data_dir = data_dir
        self.users = pd.read_csv(os.path.join(data_dir, 'user_identities.csv'))
        self.audit = pd.read_csv(os.path.join(data_dir, 'user_audit_log.csv'))
        self.ef = pd.read_csv(os.path.join(data_dir, 'evidence_files.csv')).set_index('file_id')
        self.ef['dt'] = pd.to_datetime(self.ef['captured_at'])
        self.sa = pd.read_csv(os.path.join(data_dir, 'system_activity.csv'))
        self.sa['dt'] = pd.to_datetime(self.sa['event_time'])
        
        self._init_identities()
        self._init_security_audit()
        self._init_data_catalog()
        self._init_dw_events()

    def _init_identities(self):
        self.e2u = {}
        self.u2idents = defaultdict(lambda: {'emails': set(), 'phones': set(), 'names': set(), 'hashes': set()})
        for _, r in self.users.iterrows():
            uid = r['user_id']
            em = str(r['email']).lower()
            self.e2u[em] = uid
            self.u2idents[uid]['emails'].add(em)
            if pd.notna(r['name']): self.u2idents[uid]['names'].add(str(r['name']).lower())
            if pd.notna(r['phone']): self.u2idents[uid]['phones'].add(str(r['phone']))
            if pd.notna(r['email_hash']): self.u2idents[uid]['hashes'].add(str(r['email_hash']).lower())
        for _, r in self.audit.iterrows():
            uid = r['user_id']
            fn = r['field_name']
            old_v = str(r['old_value']) if pd.notna(r['old_value']) else None
            new_v = str(r['new_value']) if pd.notna(r['new_value']) else None
            if fn == 'email':
                if old_v: self.e2u[old_v.lower()] = uid; self.u2idents[uid]['emails'].add(old_v.lower())
                if new_v: self.e2u[new_v.lower()] = uid; self.u2idents[uid]['emails'].add(new_v.lower())
            elif fn == 'phone':
                if old_v: self.u2idents[uid]['phones'].add(old_v)
                if new_v: self.u2idents[uid]['phones'].add(new_v)
            elif fn == 'name':
                if old_v: self.u2idents[uid]['names'].add(old_v.lower())
                if new_v: self.u2idents[uid]['names'].add(new_v.lower())

    def _init_security_audit(self):
        self.u2audit = {}
        for _, r in self.sa.iterrows():
            rid = str(r['resource_id'])
            if 'audit_record' in rid:
                m = re.search(r'(user_\d+)', str(r['details']))
                if m: self.u2audit[m.group(1)] = rid
        for _, r in self.ef[self.ef['origin'] == 'records_assurance_snapshot_bundle'].iterrows():
            p = os.path.join(self.data_dir, r['file_path'])
            try:
                with open(p, 'r', encoding='utf-8') as f: d = json.load(f)
                for s in d.get('snapshots', []):
                    for rec in s.get('records', []):
                        rid = rec.get('resource_id', '')
                        sref = rec.get('subject_reference')
                        if 'audit_record' in rid and sref: self.u2audit[sref] = rid
            except Exception: pass
        for _, r in self.ef[self.ef['origin'] == 'service_resource_export'].iterrows():
            p = os.path.join(self.data_dir, r['file_path'])
            try:
                with open(p, 'r', encoding='utf-8') as f: d = json.load(f)
                for rec in d.get('service_exports', {}).get('security_service', {}).get('audit_records', []):
                    rid = rec.get('resource_id', '')
                    sref = rec.get('subject_reference')
                    if rid and sref: self.u2audit[sref] = rid
            except Exception: pass
        for _, r in self.ef[self.ef['origin'] == 'customer_data_inventory_capture'].iterrows():
            p = os.path.join(self.data_dir, r['file_path'])
            try:
                conn = sqlite3.connect(':memory:')
                with open(p, 'r', encoding='utf-8', errors='ignore') as f: conn.executescript(f.read())
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_audit_records'")
                if cur.fetchone():
                    cur.execute("SELECT resource_id, subject_reference FROM security_audit_records")
                    for rid, sref in cur.fetchall():
                        if rid and sref: self.u2audit[sref] = rid
                conn.close()
            except Exception: pass
        for _, r in self.ef[self.ef['file_path'].str.endswith('.log') | self.ef['file_path'].str.endswith('.txt')].iterrows():
            p = os.path.join(self.data_dir, r['file_path'])
            try:
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if 'audit_record' in line:
                            m = re.search(r'resource_id=(audit_record_\d+).*?(?:subject_reference|subject_ref|lookup_key)=(user_\d+)', line)
                            if not m: m = re.search(r'(?:subject_reference|subject_ref|lookup_key)=(user_\d+).*?resource_id=(audit_record_\d+)', line)
                            if m:
                                if 'audit_record' in m.group(1): self.u2audit[m.group(2)] = m.group(1)
                                else: self.u2audit[m.group(1)] = m.group(2)
                            m_txt = re.search(r'\|\s*security_service\s*\|\s*(audit_record_\d+)\s*\|\s*SECURITY_AUDIT_LOG\s*\|\s*FOUND\s*\|\s*(user_\d+)', line)
                            if m_txt: self.u2audit[m_txt.group(2)] = m_txt.group(1)
            except Exception: pass

    def _init_data_catalog(self):
        self.catalog = {}
        for _, r in self.sa[self.sa['event_type'] == 'LINK_RESOURCE_IDENTITY'].iterrows():
            det = str(r['details'])
            rid = str(r['resource_id'])
            for u in self.u2idents:
                if u in det or any(e in det.lower() for e in self.u2idents[u]['emails']):
                    self.catalog[(u, r['target_system'])] = (rid, r['details'])

    def _init_dw_events(self):
        self.dw = self.sa[self.sa['source_system'] == 'deletion_worker'].copy()

    def is_user_match(self, val, uid):
        if not val or val == 'null' or val == 'None': return False
        v = str(val).strip().lower()
        if v == uid.lower(): return True
        ids = self.u2idents[uid]
        return (v in ids['emails'] or v in ids['phones'] or v in ids['names'] or v in ids['hashes'])

    def solve_case(self, case_row):
        cid = case_row['case_id']
        em = str(case_row['email']).lower()
        uid = self.e2u.get(em)
        req_text = str(case_row['request_text'])
        rep_status = case_row['reported_status']
        rep_at = case_row['reported_at']
        audit_at = case_row['audit_at']
        audit_dt = pd.to_datetime(audit_at)
        rep_dt = pd.to_datetime(rep_at)

        # 1. Intent check
        non_del_phrases = [
            'leave the account active', 'not asking for deletion', 'keep the account as it is',
            'do not close the account', 'without removing any of my records', 'marketing lists only',
            'not a request to erase', 'leave my profile and purchase history in place',
            'want to continue using the service', "don't delete or change anything",
            'download my account information', 'resetting the login'
        ]
        if any(p in req_text.lower() for p in non_del_phrases):
            return {'case_id': cid, 'deletion_status': 'NOT_APPLICABLE', 'steps_json': '[]'}

        # 2. Find Candidate Evidence
        # Evidence files at or before audit_at
        cand_ef = self.ef[self.ef['dt'] <= audit_dt].sort_values('dt', ascending=False)
        
        # Check special individual evidence first
        # Evidence 54 (customer_accounts_failover_replica_20260902.sql)
        # Evidence 57 (customer_search_primary_20260910.sql)
        # Evidence 58 (delivery_correction_attachment.pdf)
        # Evidence 59 (customer_export_jobs_20260914.json)
        # Evidence 61 (support_replica.log)
        # Evidence 03 (customer_account_handover_20261001.txt)
        # Evidence 56 (customer_analytics_report_20260907.json)

        findings = []
        remediations = []
        verifications = []

        # Let's inspect which evidence files apply to this case
        # Check if user matches any specific evidence
        pass

print("AuditSolver draft written.")
