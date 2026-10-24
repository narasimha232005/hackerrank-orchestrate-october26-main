import json
import pandas as pd

def evaluate_predictions(pred_df, gt_df):
    """
    Evaluates predictions against ground truth.
    Both DataFrames must contain: case_id, deletion_status, steps_json
    """
    merged = pd.merge(gt_df, pred_df, on='case_id', suffixes=('_gt', '_pred'))
    total_cases = len(merged)
    
    status_correct = (merged['deletion_status_gt'] == merged['deletion_status_pred']).sum()
    status_acc = status_correct / total_cases if total_cases > 0 else 0.0
    
    exact_sequence_matches = 0
    total_gt_steps = 0
    total_pred_steps = 0
    matched_steps = 0
    field_matches = {'phase': 0, 'system_id': 0, 'resource_id': 0, 'operation': 0, 'state': 0, 'evidence_id': 0}
    total_field_comparisons = 0

    case_results = []

    for _, row in merged.iterrows():
        cid = row['case_id']
        s_gt = row['deletion_status_gt']
        s_pred = row['deletion_status_pred']
        steps_gt = json.loads(row['steps_json_gt'])
        steps_pred = json.loads(row['steps_json_pred'])
        
        total_gt_steps += len(steps_gt)
        total_pred_steps += len(steps_pred)
        
        # Check exact sequence match (including step_no, all fields)
        is_exact = (s_gt == s_pred) and (len(steps_gt) == len(steps_pred))
        if is_exact:
            for s1, s2 in zip(steps_gt, steps_pred):
                for k in ['phase', 'system_id', 'resource_id', 'operation', 'state', 'evidence_id']:
                    if str(s1.get(k, '')).strip() != str(s2.get(k, '')).strip():
                        is_exact = False
                        break
                if not is_exact:
                    break
        if is_exact:
            exact_sequence_matches += 1
            
        # Match steps for precision / recall
        gt_keys = [(s['phase'], s['system_id'], s['resource_id'], s['operation'], s['state']) for s in steps_gt]
        pred_keys = [(s['phase'], s['system_id'], s['resource_id'], s['operation'], s['state']) for s in steps_pred]
        
        matches = 0
        used_pred = set()
        for gk in gt_keys:
            for j, pk in enumerate(pred_keys):
                if j not in used_pred and gk == pk:
                    matches += 1
                    used_pred.add(j)
                    break
        matched_steps += matches
        
        # Field accuracy on corresponding index if length matches
        min_len = min(len(steps_gt), len(steps_pred))
        for i in range(min_len):
            total_field_comparisons += 1
            for k in field_matches:
                if str(steps_gt[i].get(k, '')).strip() == str(steps_pred[i].get(k, '')).strip():
                    field_matches[k] += 1
                    
        case_results.append({
            'case_id': cid,
            'status_gt': s_gt,
            'status_pred': s_pred,
            'status_match': s_gt == s_pred,
            'exact_match': is_exact,
            'gt_steps_len': len(steps_gt),
            'pred_steps_len': len(steps_pred)
        })

    seq_acc = exact_sequence_matches / total_cases if total_cases > 0 else 0.0
    step_recall = matched_steps / total_gt_steps if total_gt_steps > 0 else 1.0
    step_prec = matched_steps / total_pred_steps if total_pred_steps > 0 else 1.0
    step_f1 = (2 * step_prec * step_recall / (step_prec + step_recall)) if (step_prec + step_recall) > 0 else 0.0
    
    field_accs = {k: (field_matches[k] / total_field_comparisons if total_field_comparisons > 0 else 0.0) for k in field_matches}

    report = {
        'total_cases': total_cases,
        'status_accuracy': status_acc,
        'exact_sequence_accuracy': seq_acc,
        'exact_sequence_matches': exact_sequence_matches,
        'step_precision': step_prec,
        'step_recall': step_recall,
        'step_f1': step_f1,
        'total_gt_steps': total_gt_steps,
        'total_pred_steps': total_pred_steps,
        'matched_steps': matched_steps,
        'field_accuracies': field_accs,
        'case_results': case_results
    }
    return report

if __name__ == '__main__':
    gt = pd.read_csv('dataset/sample_output.csv')
    res = evaluate_predictions(gt, gt)
    print("Self-test on ground truth:")
    print(f"Status Accuracy: {res['status_accuracy']*100:.2f}%")
    print(f"Exact Sequence Accuracy: {res['exact_sequence_accuracy']*100:.2f}%")
    print(f"Step F1: {res['step_f1']*100:.2f}%")
