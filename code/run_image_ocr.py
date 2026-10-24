import os
import easyocr
import pandas as pd

reader = easyocr.Reader(['en'], gpu=False)

ef = pd.read_csv('dataset/evidence_files.csv')
pngs = ef[ef['file_path'].str.endswith('.png')]

print(f"Running EasyOCR on {len(pngs)} images...")
results = {}
for _, r in pngs.iterrows():
    p = os.path.join('dataset', r['file_path'])
    text_list = reader.readtext(p, detail=0)
    text = "\n".join(text_list)
    results[r['file_id']] = text
    print(f"\n=== {r['file_id']} ({r['file_path']}) ===")
    print(text[:300] + ("..." if len(text) > 300 else ""))

# Save all image text to a json cache
import json
with open('code/image_ocr_cache.json', 'w', encoding='utf-8') as f:
    json.dump(results, f, indent=2)
print("\nSaved OCR results to code/image_ocr_cache.json")
