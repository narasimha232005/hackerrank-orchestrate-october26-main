import pandas as pd
import json

df_samples = pd.read_csv('dataset/sample_output.csv')

phase_order = {'FINDING': 1, 'REMEDIATION': 2, 'VERIFICATION': 3}
finding_ops = ['REPORT_REMAINING_RECORD', 'REPORT_EXPOSED_PII', 'REPORT_ACTIVE_DATA_FLOW', 'REPORT_RESTORE_RISK']
remed_ops = ['DISABLE_DATA_FLOW', 'BLOCK_RESTORE', 'DELETE_RECORD', 'REDACT_RECORD', 'ANONYMIZE_RECORD']
verif_ops = ['VERIFY_RECORD_ABSENT', 'VERIFY_RECORD_PRESENT', 'VERIFY_RECORD_REDACTED', 'VERIFY_RECORD_ANONYMIZED', 'VERIFY_DATA_FLOW_DISABLED', 'VERIFY_RESTORE_BLOCKED']

op_order = {op: i for i, op in enumerate(finding_ops + remed_ops + verif_ops)}

all_passed = True
for _, r in df_samples.iterrows():
    cid = r['case_id']
    steps = json.loads(r['steps_json'])
    # Check step numbering
    for i, s in enumerate(steps):
        if s['step_no'] != i + 1:
            print(f"{cid}: step_no mismatch: expected {i+1}, got {s['step_no']}")
            all_passed = False
            
    # Check sort order
    def sort_key(s):
        return (phase_order[s['phase']], op_order[s['operation']], s['system_id'], s['resource_id'])
        
    for i in range(len(steps) - 1):
        k1 = sort_key(steps[i])
        k2 = sort_key(steps[i+1])
        if k1 > k2:
            print(f"{cid}: ORDER ERROR between step {i+1} and {i+2}!")
            print(f"   Step {i+1}: {steps[i]}")
            print(f"   Step {i+2}: {steps[i+1]}")
            all_passed = False

if all_passed:
    print("ALL 32 SAMPLE CASES STRICTLY FOLLOW THE SPECIFIED SORT ORDER!")
