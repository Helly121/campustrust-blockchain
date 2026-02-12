import io
import hashlib
from werkzeug.datastructures import FileStorage

def get_file_hash(file_storage):
    """Compute SHA-256 hash of uploaded file (streaming)"""
    sha256 = hashlib.sha256()
    for chunk in iter(lambda: file_storage.read(4096), b""):
        sha256.update(chunk)
    file_storage.seek(0)  # reset for potential re-use
    return sha256.hexdigest()

# Simulate file upload
content = b"This is a test PDF content."
file = FileStorage(stream=io.BytesIO(content), filename="test.pdf")

# Simulate app.py logic
# 1. Save (simulated by reading to end)
print(f"Stream position before save: {file.stream.tell()}")
file.save(io.BytesIO()) # Saving to a dummy buffer
print(f"Stream position after save: {file.stream.tell()}")

# 2. Hash
cert_hash = get_file_hash(file)
print(f"Hash: {cert_hash}")

# Expected empty hash (sha256 of empty string)
empty_hash = hashlib.sha256(b"").hexdigest()
print(f"Empty Hash: {empty_hash}")

if cert_hash == empty_hash:
    print("BUG REPRODUCED: Hash is of empty content!")
else:
    print("Hash is correct.")
