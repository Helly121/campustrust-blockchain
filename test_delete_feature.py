from utils.blockchain_utils import store_certificate_hash, delete_certificate_on_chain, verify_certificate_on_chain
import os
import time

def test_delete():
    # 1. Create a dummy hash
    dummy_hash = os.urandom(32) # 32 bytes for SHA-256
    dummy_metadata = "Test Deletion|2024-01-01"
    
    print(f"Testing with hash: {dummy_hash.hex()}")
    
    # 2. Store it
    print("Storing certificate...")
    txid = store_certificate_hash(dummy_hash, dummy_metadata)
    if not txid:
        print("Failed to store certificate. Cannot proceed.")
        return

    print("Waiting for round...")
    time.sleep(5)
    
    # 3. Verify it exists
    print("Verifying existence...")
    result = verify_certificate_on_chain(dummy_hash)
    if not result['verified']:
        print("Certificate not found on chain after storage.")
        return
    print("Certificate verified on chain.")
    
    # 4. Delete it
    print("Attempting deletion...")
    del_txid = delete_certificate_on_chain(dummy_hash)
    
    if del_txid:
        print(f"Deletion successful. TXID: {del_txid}")
        
        # 5. Verify it's gone
        result = verify_certificate_on_chain(dummy_hash)
        if not result['verified']:
            print("Confirmed: Certificate is gone.")
        else:
            print("Error: Certificate still exists after deletion!")
    else:
        print("Deletion failed.")

if __name__ == "__main__":
    test_delete()
