import multiprocessing
from multiprocessing import Queue, Event
import string
import os
import time
from pypdf import PdfWriter, PdfReader
from pypdf._encryption import AlgV5
from pdf_recovery import recovery_manager

def test_correctness():
    pdf_r6 = "test_correctness.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    writer.encrypt("389151", algorithm="AES-256")
    with open(pdf_r6, "wb") as f:
        writer.write(f)

    reader = PdfReader(pdf_r6)
    encrypt_dict = reader.trailer.get("/Encrypt")
    u_obj = encrypt_dict.raw_get("/U")
    u_value = u_obj.original_bytes if hasattr(u_obj, "original_bytes") else u_obj.get_object()
    if isinstance(u_value, str):
        u_value = u_value.encode('latin1', errors='ignore')
    salt = u_value[32:40]
    target = u_value[:32]

    candidates = ["389151", "389150", "000000", "999999", "123456"]

    for c in candidates:
        pwd_bytes = c.encode('utf-8')[:127]
        hash_calc = AlgV5.calculate_hash(6, pwd_bytes, salt, b"")
        is_direct_match = hash_calc == target
        is_decrypt_match = reader.decrypt(c) != 0

        print(f"Candidate: {c}")
        print(f"  Direct validator: {is_direct_match}")
        print(f"  PdfReader.decrypt: {is_decrypt_match}")
        assert is_direct_match == is_decrypt_match, "Mismatch!"

    print("Correctness Test PASS")
    if os.path.exists(pdf_r6): os.remove(pdf_r6)

if __name__ == '__main__':
    test_correctness()
