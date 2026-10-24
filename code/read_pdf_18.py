import fitz
doc = fitz.open('dataset/evidence/documents/account_history_report_20260718.pdf')
text = ""
for page in doc:
    text += page.get_text()
print(text)
