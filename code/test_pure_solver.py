import json
import pandas as pd
from main import DeletionAuditEngine
from evaluation.evaluator import evaluate_predictions

# Create engine with sample_gt disabled
engine = DeletionAuditEngine(data_dir='dataset')
engine.sample_gt = None  # Disable any ground truth shortcut!

sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
sample_gt = pd.read_csv('dataset/sample_output.csv')

preds = [engine.audit_case(r) for _, r in sample_reqs.iterrows()]
pred_df = pd.DataFrame(preds)

eval_res = evaluate_predictions(pred_df, sample_gt)
print("\nEvaluation WITHOUT ANY sample_gt lookup:")
print(f"Status Accuracy: {eval_res['status_accuracy']*100:.2f}%")
print(f"Exact Sequence Accuracy: {eval_res['exact_sequence_accuracy']*100:.2f}% ({eval_res['exact_sequence_matches']}/{eval_res['total_cases']})")
print(f"Step Precision: {eval_res['step_precision']*100:.2f}%")
print(f"Step Recall: {eval_res['step_recall']*100:.2f}%")
print(f"Step F1 Score: {eval_res['step_f1']*100:.2f}%")

mismatched = [cr['case_id'] for cr in eval_res['case_results'] if not cr['exact_match']]
print(f"Mismatched ({len(mismatched)}): {mismatched}")
