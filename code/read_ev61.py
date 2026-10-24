with open('dataset/evidence/logs/support_replica.log', 'r') as f:
    for line in f:
        if 'support_002' in line or 'fatima' in line or 'support' in line:
            print(line.strip())
