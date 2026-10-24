import fitz
doc = fitz.open('dataset/evidence/documents/delivery_correction_attachment.pdf')
text = ""
for page in doc: text += page.get_text()
print(text)
