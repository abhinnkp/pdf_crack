import time
from pypdf import PdfReader, PdfWriter
from pypdf._encryption import AlgV5

writer = PdfWriter()
writer.add_blank_page(width=200, height=200)
writer.encrypt("389151", algorithm="AES-256")
with open("test_r6_debug.pdf", "wb") as f:
    writer.write(f)

reader = PdfReader("test_r6_debug.pdf")
encrypt_dict = reader.trailer.get("/Encrypt")
u_obj = encrypt_dict.raw_get("/U")
u_value = u_obj.original_bytes if hasattr(u_obj, "original_bytes") else u_obj.get_object()
if isinstance(u_value, str):
    u_value = u_value.encode('latin1', errors='ignore')
salt = u_value[32:40]
target = u_value[:32]

pwd_str = "000000"
pwd_bytes = pwd_str.encode('utf-8')[:127]

start = time.time()
for _ in range(100):
    AlgV5.calculate_hash(6, pwd_bytes, salt, b"")
end = time.time()
print(f"calculate_hash R6: {100 / (end - start):.2f} attempts/sec")

start = time.time()
for _ in range(100):
    try:
        reader.decrypt(pwd_str)
    except:
        pass
end = time.time()
print(f"reader.decrypt R6: {100 / (end - start):.2f} attempts/sec")
