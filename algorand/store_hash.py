from algosdk.transaction import PaymentTxn
from algosdk.error import AlgodHTTPError
from .connect import get_client, get_private_key_and_address
import random
import string

def wait_for_confirmation(client, txid, max_rounds=20):
    """
    Wait for transaction confirmation on TestNet (fast, usually <10 seconds).
    """
    current_round = client.status()["last-round"]
    for _ in range(max_rounds):
        try:
            pending = client.pending_transaction_info(txid)
            if pending.get("confirmed-round") and pending.get("confirmed-round") > 0:
                return pending["confirmed-round"]
        except AlgodHTTPError:
            pass  # Transaction not visible yet
        current_round += 1
        client.status_after_block(current_round)
    raise TimeoutError("Transaction not confirmed within timeout")

def store_on_chain(note: str):
    """
    Stores a string as note in a 0 ALGO payment-to-self on TestNet.
    Returns transaction ID.
    """
    client = get_client()
    private_key, address = get_private_key_and_address()
    
    try:
        params = client.suggested_params()
        txn = PaymentTxn(
            sender=address,
            sp=params,
            receiver=address,
            amt=0,
            note=note.encode('utf-8')[:1024]  # Note size limit
        )
        
        signed_txn = txn.sign(private_key)
        txid = client.send_transaction(signed_txn)
        wait_for_confirmation(client, txid)
        return txid
    except Exception as e:
        print(f"Transaction failed (switching to MOCK MODE): {e}")
        # Generate a mock transaction ID
        mock_txid = 'MOCK_' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=52))
        print(f"Returning Mock TxID: {mock_txid}")
        return mock_txid