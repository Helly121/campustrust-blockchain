from algorand.store_hash import store_on_chain
import traceback

print("Attempting to store hash on chain...")
try:
    txid = store_on_chain("test_note_for_debugging")
    print(f"Success! TxID: {txid}")
except Exception:
    print("Caught expected exception:")
    traceback.print_exc()
