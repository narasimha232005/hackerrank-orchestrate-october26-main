from PIL import Image
import os
import pandas as pd

ef = pd.read_csv('dataset/evidence_files.csv')
pngs = ef[ef['file_path'].str.endswith('.png')]

for _, r in pngs.iterrows():
    p = os.path.join('dataset', r['file_path'])
    im = Image.open(p)
    print(f"{r['file_id']} ({r['file_path']}): format={im.format}, size={im.size}, mode={im.mode}, info={im.info}")
