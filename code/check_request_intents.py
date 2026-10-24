import sys
sys.stdout.reconfigure(encoding='utf-8')
import pandas as pd

df = pd.read_csv('dataset/deletion_requests.csv')
sample_df = pd.read_csv('dataset/sample_deletion_requests.csv')

print(f"Total requests: {len(df)}")
# Let's inspect unique patterns in request_text
texts = df['request_text'].tolist()

# Let's check keywords for access/export/update vs delete
delete_keywords = [
    'delete', 'deletion', 'erase', 'erasure', 'remove', 'close', 'supprimer', 'suppression',
    'eliminar', 'eliminación', 'borrar', 'löschen', 'löschung', 'cancella', 'cancellazione',
    '삭제', '탈퇴', '지워', '消去', '削除', 'apagar', 'excluir', 'exclusão', 'удалить', 'удаление'
]

non_delete = []
for idx, r in df.iterrows():
    t = r['request_text'].lower()
    has_del = any(kw in t for kw in delete_keywords)
    if not has_del:
        non_delete.append((r['case_id'], r['request_text']))

print(f"Requests WITHOUT explicit deletion keywords: {len(non_delete)}")
for c, t in non_delete:
    print(f"  {c}: {t}")
