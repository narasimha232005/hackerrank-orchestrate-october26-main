from solve_all import DeletionAuditor
a = DeletionAuditor()
req = a.users[a.users['user_id'] == 'user_11'].iloc[0]
print(f"user_11: {req['email']}, {req['name']}, {req['phone']}")
with open('dataset/evidence/records/customer_account_handover_20261001.txt', 'r', encoding='utf-8') as f:
    for line in f:
        if 'search_052' in line or 'analytics_2034' in line or 'support_864' in line or 'data_flow_9522' in line:
            print("LINE:", line.strip())
