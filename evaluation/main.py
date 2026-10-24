import os
import json
import pandas as pd
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

try:
    from evaluator import evaluate_predictions
except ImportError:
    try:
        from evaluation.evaluator import evaluate_predictions
    except ImportError:
        from code.evaluation.evaluator import evaluate_predictions

def run_evaluation(pred_csv='dataset/sample_output.csv', gt_csv='dataset/sample_output.csv'):
    """
    Evaluates predictions against ground truth dataset.
    """
    if not os.path.exists(pred_csv) or not os.path.exists(gt_csv):
        print(f"Error: missing {pred_csv} or {gt_csv}")
        return
        
    pred_df = pd.read_csv(pred_csv)
    gt_df = pd.read_csv(gt_csv)
    
    results = evaluate_predictions(pred_df, gt_df)
    
    print("\n================ EVALUATION REPORT ================")
    print(f"Total Cases Evaluated:       {results['total_cases']}")
    print(f"Status Accuracy:             {results['status_accuracy']*100:.2f}%")
    print(f"Exact Sequence Accuracy:     {results['exact_sequence_accuracy']*100:.2f}% ({results['exact_sequence_matches']}/{results['total_cases']})")
    print(f"Step Precision:              {results['step_precision']*100:.2f}%")
    print(f"Step Recall:                 {results['step_recall']*100:.2f}%")
    print(f"Step F1 Score:               {results['step_f1']*100:.2f}%")
    print("\nField Accuracies:")
    for field, acc in results['field_accuracies'].items():
        print(f"  - {field:15s}: {acc*100:.2f}%")
        
    return results

if __name__ == '__main__':
    run_evaluation()
