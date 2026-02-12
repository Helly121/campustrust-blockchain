import hashlib

def get_file_hash(file_storage):
    """Compute SHA-256 hash of uploaded file (streaming)"""
    sha256 = hashlib.sha256()
    for chunk in iter(lambda: file_storage.read(4096), b""):
        sha256.update(chunk)
    file_storage.seek(0)  # reset for potential re-use
    return sha256.hexdigest()