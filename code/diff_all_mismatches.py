from solve_all import DeletionAuditor
import pandas as pd
import json

auditor = DeletionAuditor()
reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
gt = pd.read_csv('dataset/sample_output.csv').set_index('case_id')

for _, r in reqs.iterrows():
    cid = r['case_id']
    pred = auditor.audit_case(r)
    gt_row = gt.loc[cid]
    gt_status = gt_row['deletion_status']
    pred_status = pred['deletion_status']
    
    gt_steps = json.loads(gt_row['steps_json'])
    pred_steps = json.loads(pred['steps_json'])
    
    if gt_status != pred_status or gt_steps != pred_steps:
        print(f"==================== {cid} ====================")
        print(f"Status: GT={gt_status} vs PRED={pred_status}")
        gt_fmt = [f"({s['step_no']}, {s['phase']}, {s['system_id']}, {s['resource_id']}, {s['operation']}, {s['state']}, '{s['evidence_id']}')" for s in gt_steps]
        pred_fmt = [f"({s['step_no']}, {s['phase']}, {s['system_id']}, {s['resource_id']}, {s['operation']}, {s['state']}, '{s['evidence_id']}')" for s in pred_steps]
        print("GT steps:")
        for s in gt_fmt: print("  ", s)
        print("PRED steps:")
        for s in pred_fmt: print("  ", s)
