with open('dataset/evidence/logs/search_index_diagnostic_20260906.log', 'r') as f:
    lines = [f.readline() for _ in range(25)]
for l in lines:
    print(l.strip())
