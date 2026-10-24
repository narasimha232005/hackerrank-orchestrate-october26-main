import os
import sqlite3
import pandas as pd

ef = pd.read_csv('dataset/evidence_files.csv')
sqls = ef[ef['file_path'].str.endswith('.sql')]

print(f"Total SQL files: {len(sqls)}")

for _, r in sqls.iterrows():
    p = os.path.join('dataset', r['file_path'])
    # Connect in-memory sqlite and run script
    try:
        conn = sqlite3.connect(':memory:')
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            script = f.read()
        conn.executescript(script)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [t[0] for t in cur.fetchall()]
        t_counts = {}
        for t in tables:
            cur.execute(f"SELECT COUNT(*) FROM {t}")
            t_counts[t] = cur.fetchone()[0]
        print(f"{r['file_id']} ({r['file_path']}) -> Tables: {t_counts}")
        conn.close()
    except Exception as e:
        print(f"{r['file_id']} ERROR: {e}")
