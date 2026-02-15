import os
import base64
from algosdk import transaction
from connect import get_client, get_private_key_and_address
from deploy_certificate import compile_program, wait_for_confirmation
import sys

# Add parent directory to path to import contracts
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from algorand.contracts import certificate_contract

def update_app():
    client = get_client()
    private_key, sender_address = get_private_key_and_address()
    
    # 1. Compile PyTeal to TEAL
    print("Generating TEAL from PyTeal...")
    with open("certificate_contract.teal", "w") as f:
        f.write(certificate_contract.approval_program())
    with open("certificate_clear.teal", "w") as f:
        f.write(certificate_contract.clear_state_program())

    # 2. Read TEAL files
    with open("certificate_contract.teal", "r") as f:
        approval_source = f.read()
    with open("certificate_clear.teal", "r") as f:
        clear_source = f.read()

    print("Compiling approval program logic...")
    approval_program = compile_program(client, approval_source)
    print("Compiling clear program logic...")
    clear_program = compile_program(client, clear_source)

    # 3. Get App ID
    try:
        with open("certificate_app_id.txt", "r") as f:
            app_id = int(f.read().strip())
    except FileNotFoundError:
        print("Error: App ID file not found. Deploy first.")
        return

    print(f"Updating application {app_id}...")
    
    params = client.suggested_params()

    txn = transaction.ApplicationUpdateTxn(
        sender=sender_address,
        sp=params,
        index=app_id,
        approval_program=approval_program,
        clear_program=clear_program
    )

    signed_txn = txn.sign(private_key)
    tx_id = signed_txn.transaction.get_txid()
    
    print(f"Sending update transaction {tx_id}...")
    client.send_transaction(signed_txn)
    
    wait_for_confirmation(client, tx_id)
    print(f"Application {app_id} updated successfully.")

if __name__ == "__main__":
    update_app()
