import pandas as pd
import json

gt = pd.read_csv('dataset/sample_output.csv').set_index('case_id')
for cid, row in gt.iterrows():
    steps = json.loads(row['steps_json'])
    findings = [s for s in steps if s['phase'] == 'FINDING']
    verifs = [s for s in steps if s['phase'] == 'VERIFICATION']
    f_str = ', '.join([f"{f['system_id']}:{f['resource_id']}:{f['operation']}:{f['evidence_id']}" for f in findings])
    v_str = ', '.join([f"{v['system_id']}:{v['resource_id']}:{v['operation']}:{v['evidence_id']}" for v in verifs])
    print(f"{cid} ({row['deletion_status']}):\n  FINDINGS: [{f_str}]\n  VERIFS:   [{v_str}]")
