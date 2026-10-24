import pandas as pd
import json

df_samples = pd.read_csv('dataset/sample_output.csv')

for _, r in df_samples[df_samples['deletion_status'] == 'INCOMPLETE'].iterrows():
    cid = r['case_id']
    steps = json.loads(r['steps_json'])
    findings = [s for s in steps if s['phase'] == 'FINDING']
    remeds = [s for s in steps if s['phase'] == 'REMEDIATION']
    verifs = [s for s in steps if s['phase'] == 'VERIFICATION']
    
    print(f"\n=== {cid} ===")
    print("FINDINGS:")
    for f in findings:
        print(f"  {f['system_id']} / {f['resource_id']} : {f['operation']} ({f['state']}) ev={f['evidence_id']}")
    print("REMEDIATION:")
    for m in remeds:
        print(f"  {m['system_id']} / {m['resource_id']} : {m['operation']} ({m['state']})")
    print("VERIFICATION:")
    for v in verifs:
        print(f"  {v['system_id']} / {v['resource_id']} : {v['operation']} ({v['state']})")
