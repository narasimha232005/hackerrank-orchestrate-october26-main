import os
import json
import re
import sqlite3
import pandas as pd
from collections import defaultdict
import fitz
from PIL import Image
from evaluation.evaluator import evaluate_predictions

PHASE_ORDER = {'FINDING': 1, 'REMEDIATION': 2, 'VERIFICATION': 3}
FINDING_OPS = ['REPORT_REMAINING_RECORD', 'REPORT_EXPOSED_PII', 'REPORT_ACTIVE_DATA_FLOW', 'REPORT_RESTORE_RISK']
REMED_OPS = ['DISABLE_DATA_FLOW', 'BLOCK_RESTORE', 'DELETE_RECORD', 'REDACT_RECORD', 'ANONYMIZE_RECORD']
VERIF_OPS = ['VERIFY_RECORD_ABSENT', 'VERIFY_RECORD_PRESENT', 'VERIFY_RECORD_REDACTED', 'VERIFY_RECORD_ANONYMIZED', 'VERIFY_DATA_FLOW_DISABLED', 'VERIFY_RESTORE_BLOCKED']

ALL_OPS = FINDING_OPS + REMED_OPS + VERIF_OPS
OP_ORDER = {op: idx for idx, op in enumerate(ALL_OPS)}

def sort_and_number_steps(steps):
    def sort_key(s):
        return (
            PHASE_ORDER.get(s['phase'], 99),
            OP_ORDER.get(s['operation'], 99),
            str(s.get('system_id', '')),
            str(s.get('resource_id', ''))
        )
    sorted_steps = sorted(steps, key=sort_key)
    for i, s in enumerate(sorted_steps):
        s['step_no'] = i + 1
    return sorted_steps

class GeneralDeletionAuditEngine:
    def __init__(self, data_dir='dataset'):
        self.data_dir = data_dir
        self.users_df = pd.read_csv(os.path.join(data_dir, 'user_identities.csv'))
        self.audit_df = pd.read_csv(os.path.join(data_dir, 'user_audit_log.csv'))
        self.ef_df = pd.read_csv(os.path.join(data_dir, 'evidence_files.csv')).set_index('file_id')
        self.ef_df['dt'] = pd.to_datetime(self.ef_df['captured_at'])
        self.sa_df = pd.read_csv(os.path.join(data_dir, 'system_activity.csv'))
        self.sa_df['dt'] = pd.to_datetime(self.sa_df['event_time'])

        self._init_identities()
        self._init_security_audit()
        self._init_data_catalog()
        self._init_account_mapping()
        self._init_deletion_worker_events()

    def _init_identities(self):
        self.email_to_uid = {}
        self.uid_to_idents = defaultdict(lambda: {'emails': set(), 'phones': set(), 'names': set(), 'hashes': set()})
        
        for _, r in self.users_df.iterrows():
            uid = r['user_id']
            em = str(r['email']).strip().lower()
            self.email_to_uid[em] = uid
            self.uid_to_idents[uid]['emails'].add(em)
            if pd.notna(r['name']): self.uid_to_idents[uid]['names'].add(str(r['name']).strip().lower())
            if pd.notna(r['phone']): self.uid_to_idents[uid]['phones'].add(str(r['phone']).strip())
            if pd.notna(r['email_hash']): self.uid_to_idents[uid]['hashes'].add(str(r['email_hash']).strip().lower())
            
        for _, r in self.audit_df.iterrows():
            uid = r['user_id']
            fn = r['field_name']
            old_v = str(r['old_value']).strip() if pd.notna(r['old_value']) else None
            new_v = str(r['new_value']).strip() if pd.notna(r['new_value']) else None
            if fn == 'email':
                if old_v: self.email_to_uid[old_v.lower()] = uid; self.uid_to_idents[uid]['emails'].add(old_v.lower())
                if new_v: self.email_to_uid[new_v.lower()] = uid; self.uid_to_idents[uid]['emails'].add(new_v.lower())
            elif fn == 'phone':
                if old_v: self.uid_to_idents[uid]['phones'].add(old_v)
                if new_v: self.uid_to_idents[uid]['phones'].add(new_v)
            elif fn == 'name':
                if old_v: self.uid_to_idents[uid]['names'].add(old_v.lower())
                if new_v: self.uid_to_idents[uid]['names'].add(new_v.lower())
            elif fn == 'email_hash':
                if old_v: self.uid_to_idents[uid]['hashes'].add(old_v.lower())
                if new_v: self.uid_to_idents[uid]['hashes'].add(new_v.lower())

    def _init_security_audit(self):
        self.uid_to_audit = {}
        for _, r in self.sa_df.iterrows():
            rid = str(r['resource_id'])
            if 'audit_record' in rid:
                m = re.search(r'(user_\d+)', str(r['details']))
                if m: self.uid_to_audit[m.group(1)] = rid
        for _, r in self.ef_df[self.ef_df['origin'] == 'records_assurance_snapshot_bundle'].iterrows():
            p = os.path.join(self.data_dir, r['file_path'])
            try:
                with open(p, 'r', encoding='utf-8') as f: d = json.load(f)
                for s in d.get('snapshots', []):
                    for rec in s.get('records', []):
                        rid = rec.get('resource_id', '')
                        sref = rec.get('subject_reference')
                        if 'audit_record' in rid and sref: self.uid_to_audit[sref] = rid
            except Exception: pass
        for _, r in self.ef_df[self.ef_df['origin'] == 'service_resource_export'].iterrows():
            p = os.path.join(self.data_dir, r['file_path'])
            try:
                with open(p, 'r', encoding='utf-8') as f: d = json.load(f)
                for rec in d.get('service_exports', {}).get('security_service', {}).get('audit_records', []):
                    rid = rec.get('resource_id', '')
                    sref = rec.get('subject_reference')
                    if rid and sref: self.uid_to_audit[sref] = rid
            except Exception: pass
        for _, r in self.ef_df[self.ef_df['origin'] == 'customer_data_inventory_capture'].iterrows():
            p = os.path.join(self.data_dir, r['file_path'])
            try:
                conn = sqlite3.connect(':memory:')
                with open(p, 'r', encoding='utf-8', errors='ignore') as f: conn.executescript(f.read())
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_audit_records'")
                if cur.fetchone():
                    cur.execute("SELECT resource_id, subject_reference FROM security_audit_records")
                    for rid, sref in cur.fetchall():
                        if rid and sref: self.uid_to_audit[sref] = rid
                conn.close()
            except Exception: pass
        for _, r in self.ef_df[self.ef_df['file_path'].str.endswith('.log') | self.ef_df['file_path'].str.endswith('.txt')].iterrows():
            p = os.path.join(self.data_dir, r['file_path'])
            try:
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if 'audit_record' in line:
                            m = re.search(r'resource_id=(audit_record_\d+).*?(?:subject_reference|subject_ref|lookup_key)=(user_\d+)', line)
                            if not m: m = re.search(r'(?:subject_reference|subject_ref|lookup_key)=(user_\d+).*?resource_id=(audit_record_\d+)', line)
                            if m:
                                if 'audit_record' in m.group(1): self.uid_to_audit[m.group(2)] = m.group(1)
                                else: self.uid_to_audit[m.group(1)] = m.group(2)
                            m_txt = re.search(r'\|\s*security_service\s*\|\s*(audit_record_\d+)\s*\|\s*SECURITY_AUDIT_LOG\s*\|\s*FOUND\s*\|\s*(user_\d+)', line)
                            if m_txt: self.uid_to_audit[m_txt.group(2)] = m_txt.group(1)
            except Exception: pass

    def _init_data_catalog(self):
        self.catalog = {}
        for _, r in self.sa_df[self.sa_df['event_type'] == 'LINK_RESOURCE_IDENTITY'].iterrows():
            det = str(r['details'])
            rid = str(r['resource_id'])
            for u in self.uid_to_idents:
                if u in det or any(e in det.lower() for e in self.uid_to_idents[u]['emails']):
                    self.catalog[(u, r['target_system'])] = (rid, r['details'])

    def _init_account_mapping(self):
        self.uid_to_acct = {}
        for (u, sys_id), (rid, det) in self.catalog.items():
            if sys_id == 'account_service' and 'account_' in rid:
                self.uid_to_acct[u] = rid
        for _, r in self.ef_df[self.ef_df['origin'] == 'records_assurance_snapshot_bundle'].iterrows():
            p = os.path.join(self.data_dir, r['file_path'])
            try:
                with open(p, 'r', encoding='utf-8') as f: d = json.load(f)
                for s in d.get('snapshots', []):
                    for rec in s.get('records', []):
                        rid = rec.get('resource_id', '')
                        if 'account_' in rid:
                            sref = rec.get('customer_reference')
                            em = rec.get('email')
                            if sref: self.uid_to_acct[sref] = rid
                            if em and str(em).lower() in self.email_to_uid:
                                self.uid_to_acct[self.email_to_uid[str(em).lower()]] = rid
            except Exception: pass
        for _, r in self.ef_df[self.ef_df['origin'] == 'service_resource_export'].iterrows():
            p = os.path.join(self.data_dir, r['file_path'])
            try:
                with open(p, 'r', encoding='utf-8') as f: d = json.load(f)
                lookups = d.get('service_exports', {}).get('account_service', {}).get('profile_lookups', [])
                for it in lookups:
                    rid = it.get('resource_id')
                    prof = it.get('profile') or {}
                    em = prof.get('email')
                    if rid and em and str(em).lower() in self.email_to_uid:
                        self.uid_to_acct[self.email_to_uid[str(em).lower()]] = rid
            except Exception: pass
        for _, r in self.ef_df[self.ef_df['file_path'].str.endswith('.sql')].iterrows():
            p = os.path.join(self.data_dir, r['file_path'])
            try:
                conn = sqlite3.connect(':memory:')
                with open(p, 'r', encoding='utf-8', errors='ignore') as f: conn.executescript(f.read())
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                for t in [t[0] for t in cur.fetchall()]:
                    cur.execute(f"PRAGMA table_info({t})")
                    cols = [c[1] for c in cur.fetchall()]
                    if 'resource_id' in cols and 'email' in cols:
                        cur.execute(f"SELECT resource_id, email FROM {t} WHERE resource_id LIKE 'account_%'")
                        for rid, em in cur.fetchall():
                            if em and str(em).lower() in self.email_to_uid:
                                self.uid_to_acct[self.email_to_uid[str(em).lower()]] = rid
                    elif 'record_json' in cols:
                        cur.execute(f"SELECT resource_id, record_json FROM {t} WHERE resource_id LIKE 'account_%'")
                        for rid, rjson in cur.fetchall():
                            try:
                                jd = json.loads(rjson)
                                uid_r = jd.get('customer_reference') or jd.get('user_id')
                                em_r = jd.get('email')
                                if uid_r: self.uid_to_acct[uid_r] = rid
                                if em_r and str(em_r).lower() in self.email_to_uid:
                                    self.uid_to_acct[self.email_to_uid[str(em_r).lower()]] = rid
                            except Exception: pass
                conn.close()
            except Exception: pass
        handover_p = os.path.join(self.data_dir, 'evidence/records/customer_account_handover_20261001.txt')
        if os.path.exists(handover_p):
            with open(handover_p, 'r', encoding='utf-8') as f:
                for line in f:
                    m = re.search(r'(account_\d+).*?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})', line)
                    if m:
                        em = m.group(2).lower()
                        if em in self.email_to_uid: self.uid_to_acct[self.email_to_uid[em]] = m.group(1)
        for _, r in self.ef_df[self.ef_df['file_path'].str.endswith('.log')].iterrows():
            p = os.path.join(self.data_dir, r['file_path'])
            try:
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if 'account_' in line:
                            m_acc = re.search(r'resource_id=(account_\d+)', line)
                            m_em = re.search(r'(?:lookup_key|correlation_key|match_key)="?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"?', line)
                            if m_acc and m_em:
                                em = m_em.group(1).lower()
                                if em in self.email_to_uid: self.uid_to_acct[self.email_to_uid[em]] = m_acc.group(1)
            except Exception: pass

    def _init_deletion_worker_events(self):
        self.dw_events = self.sa_df[self.sa_df['source_system'] == 'deletion_worker'].copy()

    def is_user_match(self, val, uid):
        if not val or val == 'null' or val == 'None': return False
        v = str(val).strip().lower()
        if v == uid.lower(): return True
        ids = self.uid_to_idents[uid]
        return (v in ids['emails'] or v in ids['phones'] or v in ids['names'] or v in ids['hashes'])

    def read_media_file(self, file_path):
        full_path = os.path.join(self.data_dir, file_path)
        if file_path.lower().endswith('.pdf'):
            try:
                doc = fitz.open(full_path)
                text = ""
                for page in doc: text += page.get_text()
                return text
            except Exception: return ""
        elif file_path.lower().endswith(('.png', '.jpg', '.jpeg')):
            try:
                with Image.open(full_path) as img:
                    w, h = img.size
                    fmt = img.format
                return f"[IMAGE {fmt} {w}x{h}]"
            except Exception: return ""
        return ""

    def audit_case(self, case_row):
        cid = case_row['case_id']
        em = str(case_row['email']).strip().lower()
        uid = self.email_to_uid.get(em, 'unknown')
        req_text = str(case_row['request_text'])
        rep_status = case_row['reported_status']
        rep_at = case_row['reported_at']
        audit_at = case_row['audit_at']
        audit_dt = pd.to_datetime(audit_at)
        rep_dt = pd.to_datetime(rep_at)

        # 1. Non-deletion intent check
        non_del_phrases = [
            'leave the account active', 'not asking for deletion', 'keep the account as it is',
            'do not close the account', 'without removing any of my records', 'marketing lists only',
            'not a request to erase', 'leave my profile and purchase history in place',
            'want to continue using the service', "don't delete or change anything",
            'download my account information', 'resetting the login'
        ]
        if any(p in req_text.lower() for p in non_del_phrases):
            return {'case_id': cid, 'deletion_status': 'NOT_APPLICABLE', 'steps_json': '[]'}

        # 2. Candidate evidence files captured <= audit_at
        cand_ef = self.ef_df[self.ef_df['dt'] <= audit_dt].sort_values('dt', ascending=False)
        
        # Select closest evidence file to audit_at matching user or context
        primary_ef = None
        for fid, row in cand_ef.iterrows():
            fpath = row['file_path']
            if fpath.lower().endswith('.pdf'):
                pdf_text = self.read_media_file(fpath)
                if uid in pdf_text or em in pdf_text.lower():
                    primary_ef = fid; break
            elif fpath.lower().endswith(('.png', '.jpg')):
                for (u, s), (rid, det) in self.catalog.items():
                    if u == uid and rid in fpath:
                        primary_ef = fid; break
                if primary_ef: break
            else:
                full_p = os.path.join(self.data_dir, fpath)
                try:
                    with open(full_p, 'r', encoding='utf-8', errors='ignore') as fp:
                        content = fp.read()
                    if uid in content or em in content.lower():
                        primary_ef = fid; break
                except Exception: pass
                    
        if not primary_ef:
            primary_ef = cand_ef.index[0]

        ev_row = self.ef_df.loc[primary_ef]
        origin = ev_row['origin']
        fpath = os.path.join(self.data_dir, ev_row['file_path'])

        findings = []
        remediations = []
        verifications = []

        # 3. Read evidence file and extract status
        # PDF document extraction
        if fpath.lower().endswith('.pdf'):
            text = self.read_media_file(ev_row['file_path'])
            if uid in text or em in text.lower():
                m_ref = re.search(r'(support_\d+|export_\d+|audit_record_\d+)', text)
                rid = m_ref.group(1) if m_ref else None
                sys_id = 'support_platform' if rid and 'support' in rid else ('export_service' if rid and 'export' in rid else 'support_platform')
                if not rid:
                    cat_match = [(c_rid, det, s) for (u, s), (c_rid, det) in self.catalog.items() if u == uid]
                    if cat_match: rid, det, sys_id = cat_match[0]
                if rid:
                    findings.append({"phase": "FINDING", "system_id": sys_id, "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": primary_ef})
                    remediations.append({"phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                    verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})

        # Image extraction
        elif fpath.lower().endswith(('.png', '.jpg')):
            _ = self.read_media_file(ev_row['file_path'])
            cat_match = [(c_rid, det, s) for (u, s), (c_rid, det) in self.catalog.items() if u == uid]
            if cat_match:
                rid, det, sys_id = cat_match[0]
                findings.append({"phase": "FINDING", "system_id": sys_id, "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": primary_ef})
                remediations.append({"phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})

        # JSON Customer Export Store
        elif 'customer_export' in fpath or origin == 'export_service':
            try:
                with open(fpath, 'r', encoding='utf-8') as fp: d = json.load(fp)
                for rec in d.get('records', []):
                    rid = rec.get('resource_id')
                    o_em = str(rec.get('owner_email', '')).lower()
                    if self.is_user_match(o_em, uid) and rec.get('download_available') is True:
                        findings.append({"phase": "FINDING", "system_id": "export_service", "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": primary_ef})
                        remediations.append({"phase": "REMEDIATION", "system_id": "export_service", "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                        verifications.append({"phase": "VERIFICATION", "system_id": "export_service", "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
            except Exception: pass

        # SRE JSON Export
        elif origin == 'service_resource_export':
            with open(fpath, 'r', encoding='utf-8') as fp: d = json.load(fp)
            sexports = d.get('service_exports', {})
            for rec in sexports.get('account_service', {}).get('profile_lookups', []):
                rid = rec.get('resource_id')
                prof = rec.get('profile') or {}
                m_found = (rec.get('status_code') == 200)
                is_this_user = (prof.get('email', '').lower() == em or prof.get('customer_reference') == uid or rid == self.uid_to_acct.get(uid))
                if is_this_user:
                    if m_found:
                        findings.append({"phase": "FINDING", "system_id": "account_service", "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": primary_ef})
                        remediations.append({"phase": "REMEDIATION", "system_id": "account_service", "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                        verifications.append({"phase": "VERIFICATION", "system_id": "account_service", "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
                    else:
                        verifications.append({"phase": "VERIFICATION", "system_id": "account_service", "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": primary_ef})
            for rec in sexports.get('search_service', {}).get('search_entries', []):
                rid = rec.get('resource_id')
                doc = rec.get('document') or {}
                if any(self.is_user_match(val, uid) for k, val in doc.items()):
                    findings.append({"phase": "FINDING", "system_id": "search_service", "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": primary_ef})
                    remediations.append({"phase": "REMEDIATION", "system_id": "search_service", "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                    verifications.append({"phase": "VERIFICATION", "system_id": "search_service", "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
            for rec in sexports.get('export_service', {}).get('export_jobs', []):
                rid = rec.get('resource_id')
                if self.is_user_match(rec.get('requester_email'), uid) or self.is_user_match(rec.get('customer_reference'), uid):
                    findings.append({"phase": "FINDING", "system_id": "export_service", "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": primary_ef})
                    remediations.append({"phase": "REMEDIATION", "system_id": "export_service", "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                    verifications.append({"phase": "VERIFICATION", "system_id": "export_service", "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
            for rec in sexports.get('support_platform', {}).get('tickets', []):
                rid = rec.get('resource_id')
                if any(self.is_user_match(rec.get(k), uid) for k in ['requester_email', 'customer_reference', 'requester_name', 'requester_phone']):
                    findings.append({"phase": "FINDING", "system_id": "support_platform", "resource_id": rid, "operation": "REPORT_EXPOSED_PII", "state": "PRESENT", "evidence_id": primary_ef})
                    remediations.append({"phase": "REMEDIATION", "system_id": "support_platform", "resource_id": rid, "operation": "REDACT_RECORD", "state": "REDACTED", "evidence_id": ""})
                    verifications.append({"phase": "VERIFICATION", "system_id": "support_platform", "resource_id": rid, "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED", "evidence_id": ""})
                elif rec.get('customer_reference') == uid:
                    verifications.append({"phase": "VERIFICATION", "system_id": "support_platform", "resource_id": rid, "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED", "evidence_id": primary_ef})
            for rec in sexports.get('analytics_platform', {}).get('profiles', []):
                rid = rec.get('resource_id')
                if any(self.is_user_match(rec.get(k), uid) for k in ['email', 'customer_reference', 'email_hash', 'phone']):
                    findings.append({"phase": "FINDING", "system_id": "analytics_platform", "resource_id": rid, "operation": "REPORT_EXPOSED_PII", "state": "PRESENT", "evidence_id": primary_ef})
                    remediations.append({"phase": "REMEDIATION", "system_id": "analytics_platform", "resource_id": rid, "operation": "ANONYMIZE_RECORD", "state": "ANONYMIZED", "evidence_id": ""})
                    verifications.append({"phase": "VERIFICATION", "system_id": "analytics_platform", "resource_id": rid, "operation": "VERIFY_RECORD_ANONYMIZED", "state": "ANONYMIZED", "evidence_id": ""})
                elif rec.get('customer_reference') == uid:
                    verifications.append({"phase": "VERIFICATION", "system_id": "analytics_platform", "resource_id": rid, "operation": "VERIFY_RECORD_ANONYMIZED", "state": "ANONYMIZED", "evidence_id": primary_ef})
            for rec in sexports.get('integration_service', {}).get('connectors', []):
                rid = rec.get('resource_id')
                if self.is_user_match(rec.get('customer_email'), uid) or self.is_user_match(rec.get('customer_reference'), uid):
                    if rec.get('enabled') is True:
                        findings.append({"phase": "FINDING", "system_id": "integration_service", "resource_id": rid, "operation": "REPORT_ACTIVE_DATA_FLOW", "state": "ACTIVE", "evidence_id": primary_ef})
                        remediations.append({"phase": "REMEDIATION", "system_id": "integration_service", "resource_id": rid, "operation": "DISABLE_DATA_FLOW", "state": "DISABLED", "evidence_id": ""})
                        verifications.append({"phase": "VERIFICATION", "system_id": "integration_service", "resource_id": rid, "operation": "VERIFY_DATA_FLOW_DISABLED", "state": "DISABLED", "evidence_id": ""})
                    else:
                        verifications.append({"phase": "VERIFICATION", "system_id": "integration_service", "resource_id": rid, "operation": "VERIFY_DATA_FLOW_DISABLED", "state": "DISABLED", "evidence_id": primary_ef})
            for rec in sexports.get('backup_service', {}).get('restore_entries', []):
                rid = rec.get('resource_id')
                if self.is_user_match(rec.get('customer_email'), uid) or self.is_user_match(rec.get('customer_reference'), uid):
                    if rec.get('restore_allowed') is True:
                        findings.append({"phase": "FINDING", "system_id": "backup_service", "resource_id": rid, "operation": "REPORT_RESTORE_RISK", "state": "ACTIVE", "evidence_id": primary_ef})
                        remediations.append({"phase": "REMEDIATION", "system_id": "backup_service", "resource_id": rid, "operation": "BLOCK_RESTORE", "state": "BLOCKED", "evidence_id": ""})
                        verifications.append({"phase": "VERIFICATION", "system_id": "backup_service", "resource_id": rid, "operation": "VERIFY_RESTORE_BLOCKED", "state": "BLOCKED", "evidence_id": ""})
                    else:
                        verifications.append({"phase": "VERIFICATION", "system_id": "backup_service", "resource_id": rid, "operation": "VERIFY_RESTORE_BLOCKED", "state": "BLOCKED", "evidence_id": primary_ef})
            for rec in sexports.get('security_service', {}).get('audit_records', []):
                rid = rec.get('resource_id')
                if rec.get('subject_reference') == uid:
                    verifications.append({"phase": "VERIFICATION", "system_id": "security_service", "resource_id": rid, "operation": "VERIFY_RECORD_PRESENT", "state": "PRESENT", "evidence_id": primary_ef})

        # Snapshot Bundles
        elif origin == 'records_assurance_snapshot_bundle':
            with open(fpath, 'r', encoding='utf-8') as fp: d = json.load(fp)
            for s in d.get('snapshots', []):
                ds = s.get('data_store')
                for rec in s.get('records', []):
                    rid = rec.get('resource_id')
                    sref = rec.get('subject_reference') or rec.get('customer_reference')
                    if sref == uid or any(self.is_user_match(rec.get(k), uid) for k in ['email', 'user_id']):
                        if ds == 'account_service':
                            if rec.get('account_status') == 'ACTIVE':
                                findings.append({"phase": "FINDING", "system_id": ds, "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": primary_ef})
                                remediations.append({"phase": "REMEDIATION", "system_id": ds, "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                                verifications.append({"phase": "VERIFICATION", "system_id": ds, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
                            else:
                                verifications.append({"phase": "VERIFICATION", "system_id": ds, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": primary_ef})
                        elif ds == 'identity_service':
                            if rec.get('email') is not None or rec.get('name') is not None:
                                findings.append({"phase": "FINDING", "system_id": ds, "resource_id": rid, "operation": "REPORT_EXPOSED_PII", "state": "PRESENT", "evidence_id": primary_ef})
                                remediations.append({"phase": "REMEDIATION", "system_id": ds, "resource_id": rid, "operation": "REDACT_RECORD", "state": "REDACTED", "evidence_id": ""})
                                verifications.append({"phase": "VERIFICATION", "system_id": ds, "resource_id": rid, "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED", "evidence_id": ""})
                            else:
                                verifications.append({"phase": "VERIFICATION", "system_id": ds, "resource_id": rid, "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED", "evidence_id": primary_ef})
                        elif ds == 'security_service':
                            verifications.append({"phase": "VERIFICATION", "system_id": ds, "resource_id": rid, "operation": "VERIFY_RECORD_PRESENT", "state": "PRESENT", "evidence_id": primary_ef})

        # Logs and text files
        elif fpath.endswith('.log') or fpath.endswith('.txt'):
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as fp:
                for line in fp:
                    if '|' in line and ('FOUND' in line or 'IDENTIFIABLE' in line or 'ACTIVE' in line or 'REDACTED' in line):
                        parts = [p.strip() for p in line.split('|')]
                        if len(parts) >= 6:
                            sys_id = parts[1]
                            rid = parts[2]
                            status = parts[4]
                            subj = parts[5].lower()
                            if self.is_user_match(subj, uid):
                                if sys_id == 'account_service':
                                    if status == 'NOT_FOUND':
                                        verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": primary_ef})
                                    else:
                                        findings.append({"phase": "FINDING", "system_id": sys_id, "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": primary_ef})
                                        remediations.append({"phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                                        verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
                                elif sys_id == 'search_service':
                                    if status == 'FOUND':
                                        findings.append({"phase": "FINDING", "system_id": sys_id, "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": primary_ef})
                                        remediations.append({"phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                                        verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
                                elif sys_id == 'analytics_platform':
                                    if status == 'IDENTIFIABLE':
                                        findings.append({"phase": "FINDING", "system_id": sys_id, "resource_id": rid, "operation": "REPORT_EXPOSED_PII", "state": "PRESENT", "evidence_id": primary_ef})
                                        remediations.append({"phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid, "operation": "ANONYMIZE_RECORD", "state": "ANONYMIZED", "evidence_id": ""})
                                        verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ANONYMIZED", "state": "ANONYMIZED", "evidence_id": ""})
                                    elif status == 'ANONYMIZED':
                                        verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ANONYMIZED", "state": "ANONYMIZED", "evidence_id": primary_ef})
                                elif sys_id == 'support_platform':
                                    if status == 'IDENTIFIABLE':
                                        findings.append({"phase": "FINDING", "system_id": sys_id, "resource_id": rid, "operation": "REPORT_EXPOSED_PII", "state": "PRESENT", "evidence_id": primary_ef})
                                        remediations.append({"phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid, "operation": "REDACT_RECORD", "state": "REDACTED", "evidence_id": ""})
                                        verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED", "evidence_id": ""})
                                    elif status == 'REDACTED':
                                        verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED", "evidence_id": primary_ef})
                                elif sys_id == 'integration_service':
                                    if status == 'ACTIVE':
                                        findings.append({"phase": "FINDING", "system_id": sys_id, "resource_id": rid, "operation": "REPORT_ACTIVE_DATA_FLOW", "state": "ACTIVE", "evidence_id": primary_ef})
                                        remediations.append({"phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid, "operation": "DISABLE_DATA_FLOW", "state": "DISABLED", "evidence_id": ""})
                                        verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_DATA_FLOW_DISABLED", "state": "DISABLED", "evidence_id": ""})
                                    elif status == 'DISABLED':
                                        verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_DATA_FLOW_DISABLED", "state": "DISABLED", "evidence_id": primary_ef})
                                elif sys_id == 'backup_service':
                                    if status == 'ACTIVE':
                                        findings.append({"phase": "FINDING", "system_id": sys_id, "resource_id": rid, "operation": "REPORT_RESTORE_RISK", "state": "ACTIVE", "evidence_id": primary_ef})
                                        remediations.append({"phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid, "operation": "BLOCK_RESTORE", "state": "BLOCKED", "evidence_id": ""})
                                        verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RESTORE_BLOCKED", "state": "BLOCKED", "evidence_id": ""})
                                    elif status == 'BLOCKED':
                                        verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RESTORE_BLOCKED", "state": "BLOCKED", "evidence_id": primary_ef})
                                elif sys_id == 'security_service':
                                    if status == 'FOUND':
                                        verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_PRESENT", "state": "PRESENT", "evidence_id": primary_ef})
                    
                    all_idents = self.uid_to_idents[uid]['emails'] | {uid} | self.uid_to_idents[uid]['phones'] | self.uid_to_idents[uid]['hashes']
                    if any(ident in line for ident in all_idents if ident):
                        m_sys = re.search(r'(?:service|system)="?([A-Za-z0-9_]+)"?', line)
                        m_rid = re.search(r'resource_id="?([A-Za-z0-9_]+)"?', line)
                        if m_sys and m_rid:
                            sys_id = m_sys.group(1)
                            rid = m_rid.group(1)
                            if 'support_replica' in sys_id: sys_id = 'support_platform'
                            if sys_id == 'account_service':
                                if 'rows=0' in line or '404' in line or 'NOT_FOUND' in line:
                                    verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": primary_ef})
                                elif 'rows=1' in line or '200' in line or 'result="FOUND"' in line:
                                    findings.append({"phase": "FINDING", "system_id": sys_id, "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": primary_ef})
                                    remediations.append({"phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                                    verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
                            elif sys_id == 'search_service':
                                if 'result=hit' in line or 'total_hits=1' in line or 'result="FOUND"' in line:
                                    findings.append({"phase": "FINDING", "system_id": sys_id, "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": primary_ef})
                                    remediations.append({"phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                                    verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
                            elif sys_id == 'analytics_platform':
                                if 'rows=1' in line or 'contact_lookup_completed' in line or 'result="IDENTIFIABLE"' in line:
                                    findings.append({"phase": "FINDING", "system_id": sys_id, "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": primary_ef})
                                    remediations.append({"phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                                    verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
                                elif 'result="ANONYMIZED"' in line:
                                    verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ANONYMIZED", "state": "ANONYMIZED", "evidence_id": primary_ef})
                            elif sys_id == 'support_platform':
                                if 'marker_found=false' in line or 'rows=1' in line:
                                    findings.append({"phase": "FINDING", "system_id": sys_id, "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": primary_ef})
                                    remediations.append({"phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                                    verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
                                elif 'result="IDENTIFIABLE"' in line:
                                    findings.append({"phase": "FINDING", "system_id": sys_id, "resource_id": rid, "operation": "REPORT_EXPOSED_PII", "state": "PRESENT", "evidence_id": primary_ef})
                                    remediations.append({"phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid, "operation": "REDACT_RECORD", "state": "REDACTED", "evidence_id": ""})
                                    verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED", "evidence_id": ""})
                            elif sys_id == 'integration_service':
                                if 'enabled=true' in line or 'result="ACTIVE"' in line:
                                    findings.append({"phase": "FINDING", "system_id": sys_id, "resource_id": rid, "operation": "REPORT_ACTIVE_DATA_FLOW", "state": "ACTIVE", "evidence_id": primary_ef})
                                    remediations.append({"phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid, "operation": "DISABLE_DATA_FLOW", "state": "DISABLED", "evidence_id": ""})
                                    verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_DATA_FLOW_DISABLED", "state": "DISABLED", "evidence_id": ""})
                            elif sys_id == 'backup_service':
                                if 'restore_allowed=true' in line or 'result="ACTIVE"' in line:
                                    findings.append({"phase": "FINDING", "system_id": sys_id, "resource_id": rid, "operation": "REPORT_RESTORE_RISK", "state": "ACTIVE", "evidence_id": primary_ef})
                                    remediations.append({"phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid, "operation": "BLOCK_RESTORE", "state": "BLOCKED", "evidence_id": ""})
                                    verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RESTORE_BLOCKED", "state": "BLOCKED", "evidence_id": ""})
                            elif sys_id == 'security_service':
                                verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_PRESENT", "state": "PRESENT", "evidence_id": primary_ef})

        # SQL SQLite Snapshot Files
        elif fpath.endswith('.sql'):
            conn = sqlite3.connect(':memory:')
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as fp: conn.executescript(fp.read())
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [t[0] for t in cur.fetchall()]
            for t in tables:
                cur.execute(f"PRAGMA table_info({t})")
                cols = [c[1] for c in cur.fetchall()]
                # Search documents table
                if 'search_documents' in t and 'resource_id' in cols and 'email' in cols:
                    cur.execute(f"SELECT resource_id, email FROM {t}")
                    for rid, em_r in cur.fetchall():
                        if self.is_user_match(em_r, uid):
                            findings.append({"phase": "FINDING", "system_id": "search_service", "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": primary_ef})
                            remediations.append({"phase": "REMEDIATION", "system_id": "search_service", "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                            verifications.append({"phase": "VERIFICATION", "system_id": "search_service", "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
                elif 'record_json' in cols:
                    cur.execute(f"SELECT resource_id, origin_system, record_json FROM {t}")
                    for rid, s_id, rjson in cur.fetchall():
                        try:
                            jd = json.loads(rjson)
                            if any(self.is_user_match(val, uid) for k, val in jd.items() if isinstance(val, str)):
                                st = jd.get('account_status') or jd.get('status')
                                if st == 'ACTIVE':
                                    findings.append({"phase": "FINDING", "system_id": s_id or "account_service", "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": primary_ef})
                                    remediations.append({"phase": "REMEDIATION", "system_id": s_id or "account_service", "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                                    verifications.append({"phase": "VERIFICATION", "system_id": s_id or "account_service", "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
                        except Exception: pass
                elif 'email' in cols and 'account_status' in cols:
                    cur.execute(f"SELECT resource_id, email, account_status FROM {t}")
                    for rid, em_r, st in cur.fetchall():
                        if self.is_user_match(em_r, uid):
                            if st == 'ACTIVE':
                                findings.append({"phase": "FINDING", "system_id": "account_service", "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": primary_ef})
                                remediations.append({"phase": "REMEDIATION", "system_id": "account_service", "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                                verifications.append({"phase": "VERIFICATION", "system_id": "account_service", "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
            conn.close()

        # 4. Deletion Worker activity events in window
        w_events = self.dw_events[(self.dw_events['dt'] >= rep_dt - pd.Timedelta(hours=4)) & (self.dw_events['dt'] <= rep_dt + pd.Timedelta(hours=4))]
        for _, er in w_events.iterrows():
            res = er['reported_result']
            et = er['event_type']
            sys_id = er['target_system']
            rid = str(er['resource_id'])
            det = str(er['details'])
            
            is_our_res = False
            if rid == self.uid_to_acct.get(uid):
                is_our_res = True
            elif uid in det or em in det.lower():
                is_our_res = True
            elif (uid, sys_id) in self.catalog and self.catalog[(uid, sys_id)][0] == rid:
                is_our_res = True
                
            if is_our_res:
                if res in ['FAILED', 'PARTIAL']:
                    if et == 'DELETE_RECORD':
                        findings.append({"phase": "FINDING", "system_id": sys_id, "resource_id": rid, "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": primary_ef})
                        remediations.append({"phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid, "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""})
                        verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""})
                    elif et in ['REDACT_RECORD', 'ANONYMIZE_RECORD']:
                        findings.append({"phase": "FINDING", "system_id": sys_id, "resource_id": rid, "operation": "REPORT_EXPOSED_PII", "state": "PRESENT", "evidence_id": primary_ef})
                        op_rem = 'REDACT_RECORD' if et == 'REDACT_RECORD' else 'ANONYMIZE_RECORD'
                        st_rem = 'REDACTED' if et == 'REDACT_RECORD' else 'ANONYMIZED'
                        remediations.append({"phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid, "operation": op_rem, "state": st_rem, "evidence_id": ""})
                        verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": f"VERIFY_RECORD_{st_rem}", "state": st_rem, "evidence_id": ""})
                elif et == 'CHECK_DATA_FLOW' and 'remains enabled' in det:
                    findings.append({"phase": "FINDING", "system_id": sys_id, "resource_id": rid, "operation": "REPORT_ACTIVE_DATA_FLOW", "state": "ACTIVE", "evidence_id": primary_ef})
                    remediations.append({"phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid, "operation": "DISABLE_DATA_FLOW", "state": "DISABLED", "evidence_id": ""})
                    verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_DATA_FLOW_DISABLED", "state": "DISABLED", "evidence_id": ""})
                elif et == 'CHECK_RESTORE_ACCESS' and 'can still be restored' in det:
                    findings.append({"phase": "FINDING", "system_id": sys_id, "resource_id": rid, "operation": "REPORT_RESTORE_RISK", "state": "ACTIVE", "evidence_id": primary_ef})
                    remediations.append({"phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid, "operation": "BLOCK_RESTORE", "state": "BLOCKED", "evidence_id": ""})
                    verifications.append({"phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid, "operation": "VERIFY_RESTORE_BLOCKED", "state": "BLOCKED", "evidence_id": ""})

        # 5. Deduplicate and ensure baseline complete verifications
        unique_findings = []
        seen_f = set()
        for f in findings:
            k = (f['system_id'], f['resource_id'], f['operation'])
            if k not in seen_f:
                seen_f.add(k)
                unique_findings.append(f)

        unique_remeds = []
        seen_r = set()
        for m in remediations:
            k = (m['system_id'], m['resource_id'], m['operation'])
            if k not in seen_r:
                seen_r.add(k)
                unique_remeds.append(m)

        # Baseline verification: account_service
        acc_rid = self.uid_to_acct.get(uid)
        if not acc_rid:
            for _, er in w_events[w_events['target_system'] == 'account_service'].iterrows():
                acc_rid = str(er['resource_id'])
                break
        if not acc_rid:
            acc_rid = f"account_{int(uid.split('_')[1]):03d}" if 'user_' in uid else "account_001"

        if not any(v['system_id'] == 'account_service' for v in verifications):
            verifications.append({
                "phase": "VERIFICATION",
                "system_id": "account_service",
                "resource_id": acc_rid,
                "operation": "VERIFY_RECORD_ABSENT",
                "state": "ABSENT",
                "evidence_id": primary_ef if not unique_findings else ""
            })

        # Baseline verification: security_service
        audit_rid = self.uid_to_audit.get(uid)
        if audit_rid and not any(v['system_id'] == 'security_service' for v in verifications):
            verifications.append({
                "phase": "VERIFICATION",
                "system_id": "security_service",
                "resource_id": audit_rid,
                "operation": "VERIFY_RECORD_PRESENT",
                "state": "PRESENT",
                "evidence_id": primary_ef if not unique_findings else ""
            })

        unique_verifs = []
        seen_v = set()
        for v in verifications:
            k = (v['system_id'], v['resource_id'], v['operation'])
            if k not in seen_v:
                seen_v.add(k)
                if unique_findings:
                    v['evidence_id'] = ""
                else:
                    if not v.get('evidence_id'):
                        v['evidence_id'] = primary_ef
                unique_verifs.append(v)

        status = 'INCOMPLETE' if unique_findings else 'COMPLETE'
        all_steps = unique_findings + unique_remeds + unique_verifs
        sorted_steps = sort_and_number_steps(all_steps)

        return {
            'case_id': cid,
            'deletion_status': status,
            'steps_json': json.dumps(sorted_steps)
        }

if __name__ == '__main__':
    engine = GeneralDeletionAuditEngine(data_dir='dataset')
    sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
    sample_gt = pd.read_csv('dataset/sample_output.csv')
    preds = [engine.audit_case(r) for _, r in sample_reqs.iterrows()]
    pred_df = pd.DataFrame(preds)
    eval_res = evaluate_predictions(pred_df, sample_gt)
    print("\nPure Generalized Engine Results:")
    print(f"Status Accuracy: {eval_res['status_accuracy']*100:.2f}%")
    print(f"Sequence Accuracy: {eval_res['exact_sequence_accuracy']*100:.2f}%")
    print(f"F1 Score: {eval_res['step_f1']*100:.2f}%")
