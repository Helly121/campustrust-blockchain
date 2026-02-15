from algorand.connect import get_client, get_private_key_and_address
from algosdk.logic import get_application_address
from algosdk.transaction import PaymentTxn, wait_for_confirmation

def fund_app():
    client = get_client()
    private_key, sender_addr = get_private_key_and_address()
    
    app_id = 755556381
    app_addr = get_application_address(app_id)
    
    print(f"Funding App Account {app_addr} from {sender_addr}...")
    
    params = client.suggested_params()
    txn = PaymentTxn(
        sender=sender_addr,
        sp=params,
        receiver=app_addr,
        amt=1_000_000 # 1 ALGO
    )
    
    signed_txn = txn.sign(private_key)
    txid = client.send_transaction(signed_txn)
    
    print(f"Sent 1 ALGO. TXID: {txid}")
    wait_for_confirmation(client, txid)
    print("App Account funded successfully.")

if __name__ == "__main__":
    fund_app()
