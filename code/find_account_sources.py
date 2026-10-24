import os

accounts = [
    'account_7566', 'account_3960', 'account_4248', 'account_9797',
    'account_9335', 'account_3677', 'account_4745', 'account_994',
    'account_4092', 'account_5521', 'account_9102', 'account_5037',
    'account_6440', 'account_4990', 'account_410', 'account_5334'
]

results = {a: [] for a in accounts}

for root, dirs, files in os.walk('dataset'):
    for f in files:
        if f.endswith('.csv') and 'sample_output' in f: continue
        path = os.path.join(root, f)
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as fp:
                c = fp.read()
                for a in accounts:
                    if a in c:
                        results[a].append(path)
        except Exception:
            pass

for a, paths in results.items():
    print(f"{a}: {paths}")
