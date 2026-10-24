from solve_all import DeletionAuditor
a = DeletionAuditor()
for u in ['user_15', 'user_17']:
    idents = a.u2idents[u]['emails'] | {u} | a.u2idents[u]['phones'] | a.u2idents[u]['hashes']
    print(f"=== {u} idents ===")
    with open('dataset/evidence/logs/service_events_ap_south_20260915.log', 'r', encoding='utf-8') as f:
        for line in f:
            if any(ident in line for ident in idents if ident):
                print(line.strip())
