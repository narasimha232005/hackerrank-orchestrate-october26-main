import fitz
import os
import pandas as pd

ef = pd.read_csv('dataset/evidence_files.csv')
pdfs = ef[ef['file_path'].str.endswith('.pdf')]

for _, r in pdfs.iterrows():
    p = os.path.join('dataset', r['file_path'])
    doc = fitz.open(p)
    print(f"\n==========================================")
    print(f"FILE: {r['file_id']} ({r['file_path']})")
    print(f"Captured: {r['captured_at']}, Origin: {r['origin']}")
    print(f"Pages: {len(doc)}")
    for i, page in enumerate(doc):
        print(f"--- Page {i+1} ---")
        print(page.get_text().strip())
