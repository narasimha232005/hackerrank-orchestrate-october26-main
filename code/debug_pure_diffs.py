import json
import pandas as pd
from main import DeletionAuditEngine
from evaluation.evaluator import evaluate_predictions

engine = DeletionAuditEngine(data_dir='dataset')
sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
sample_gt = pd.read_csv('dataset/sample_output.csv').set_index('case_id')

for _, r in sample_reqs.iterrows():
    cid = r['case_id']
    pred = engine.audit_case(r)
    gt_row = sample_gt.loc[cid]
    gt_status = gt_row['deletion_status']
    pred_status = pred['deletion_status']
    gt_steps = json.loads(gt_row['steps_json'])
    pred_steps = json.loads(pred['steps_json'])
    
    if gt_status != pred_status or len(gt_steps) != len(pred_steps):
        print(f"=== {cid} ===")
        print(f"Status: GT={gt_status} vs PRED={pred_status} | Steps len: GT={len(gt_steps)} vs PRED={len(pred_steps)}")
        print("GT findings:", [s['resource_id'] for s in gt_steps if s['phase'] == 'FINDING'])
        print("PRED findings:", [s['resource_id'] for s in pred_steps if s['phase'] == 'FINDING'])
