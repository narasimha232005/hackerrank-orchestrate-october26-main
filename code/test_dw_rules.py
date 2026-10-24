import pandas as pd
import json

sa = pd.read_csv('dataset/system_activity.csv')
sa['dt'] = pd.to_datetime(sa['event_time'])
dw = sa[sa['source_system'] == 'deletion_worker'].copy()

gt = pd.read_csv('dataset/sample_output.csv').set_index('case_id')
reqs = pd.read_csv('dataset/sample_deletion_requests.csv').set_index('case_id')

for cid, row in gt.iterrows():
    req = reqs.loc[cid]
    rep_dt = pd.to_datetime(req['reported_at'])
    audit_dt = pd.to_datetime(req['audit_at'])
    
    # Let's find deletion_worker events within +/- 4 hours of reported_at
    w_events = dw[(dw['dt'] >= rep_dt - pd.Timedelta(hours=4)) & (dw['dt'] <= rep_dt + pd.Timedelta(hours=4))]
    
    steps = json.loads(row['steps_json'])
    gt_findings = [(s['system_id'], s['resource_id'], s['operation']) for s in steps if s['phase'] == 'FINDING']
    
    # Check what failed/partial/check events occurred in this window
    dw_violations = []
    for _, er in w_events.iterrows():
        res = er['reported_result']
        et = er['event_type']
        sys_id = er['target_system']
        rid = er['resource_id']
        det = er['details']
        if res in ['FAILED', 'PARTIAL'] or et in ['CHECK_DATA_FLOW', 'CHECK_RESTORE_ACCESS']:
            dw_violations.append((sys_id, rid, et, res))
            
    print(f"{cid} (GT: {len(gt_findings)} findings):")
    print(f"   GT findings: {gt_findings}")
    print(f"   DW in window ({len(w_events)} events, {len(dw_violations)} violations): {dw_violations}")
