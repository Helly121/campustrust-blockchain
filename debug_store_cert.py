from utils.blockchain_utils import store_certificate_hash
from algorand.connect import get_client
import hashlib
import datetime
import random

def test_store():
    # Simulate data
    random_content = str(random.random()).encode('utf-8')
    cert_hash = hashlib.sha256(random_content).hexdigest()
    cert_hash_bytes = bytes.fromhex(cert_hash)
    
    # Simulate Admin Metadata
    # Admin might have None student_id, so let's test that case if we pick a strict type.
    # But python f-string converts None to "None".
    target_student_id = "STU-DEBUG-001"
    admin_name = "Admin User"
    metadata = f"{target_student_id}|{admin_name}|{datetime.datetime.now().isoformat()}"
    
    print(f"Testing store_certificate_hash...")
    print(f"Hash: {cert_hash}")
    print(f"Metadata: {metadata}")
    
    try:
        txid = store_certificate_hash(cert_hash_bytes, metadata)
        if txid:
            print(f"Success! TXID: {txid}")
        else:
            print("Failed: store_certificate_hash returned None")
    except Exception as e:
        print(f"Exception during test: {e}")

if __name__ == "__main__":
    test_store()
