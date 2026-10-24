import os, re, pandas as pd
ef = pd.read_csv('dataset/evidence_files.csv')
pattern = re.compile(r'\b(user_18|ingrid\.dahl@outlook\.com)\b', re.IGNORECASE)

for _, r in ef.iterrows():
    fpath = os.path.join('dataset', r['file_path'])
    if not os.path.exists(fpath): continue
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as fp:
            content = fp.read()
        m = pattern.findall(content)
        if m:
            print(f"{r['file_id']} ({r['captured_at']}, {r['origin']}): matches {set(m)}")
    except Exception:
        pass
