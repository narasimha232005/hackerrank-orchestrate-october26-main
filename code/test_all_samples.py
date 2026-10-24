import json
import os
import re
import sqlite3
import pandas as pd
from collections import defaultdict
from evaluation.evaluator import evaluate_predictions

# Phase and Op ordering
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

print("Helper defined.")
