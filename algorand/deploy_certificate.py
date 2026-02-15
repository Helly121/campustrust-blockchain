import os
import base64
from algosdk import account, mnemonic, transaction
from algosdk.v2client import algod
from connect import get_client, get_private_key_and_address

def compile_program(client, source_code):
    compile_response = client.compile(source_code)
    return base64.b64decode(compile_response['result'])

def deploy_app():
    client = get_client()
    private_key, sender_address = get_private_key_and_address()

    # Read TEAL files
    with open("certificate_contract.teal", "r") as f:
        approval_source = f.read()
    with open("certificate_clear.teal", "r") as f:
        clear_source = f.read()

    print("Compiling approval program...")
    approval_program = compile_program(client, approval_source)
    print("Compiling clear program...")
    clear_program = compile_program(client, clear_source)

    print("Deploying application...")
    
    # Declare global schema (0 ints, 0 bytes) 
    # Declare local schema (0 ints, 0 bytes)
    # Box storage doesn't need global schema declarations
    global_schema = transaction.StateSchema(num_uints=0, num_byte_slices=0)
    local_schema = transaction.StateSchema(num_uints=0, num_byte_slices=0)

    params = client.suggested_params()

    txn = transaction.ApplicationCreateTxn(
        sender=sender_address,
        sp=params,
        on_complete=transaction.OnComplete.NoOpOC,
        approval_program=approval_program,
        clear_program=clear_program,
        global_schema=global_schema,
        local_schema=local_schema
    )

    signed_txn = txn.sign(private_key)
    tx_id = signed_txn.transaction.get_txid()
    
    print(f"Sending transaction {tx_id}...")
    client.send_transaction(signed_txn)
    
    wait_for_confirmation(client, tx_id)
    
    transaction_response = client.pending_transaction_info(tx_id)
    app_id = transaction_response['application-index']
    print(f"Deployed App ID: {app_id}")
    
    # Write App ID to a file for other scripts to use
    with open("certificate_app_id.txt", "w") as f:
        f.write(str(app_id))
        
    return app_id

def wait_for_confirmation(client, txid):
    last_round = client.status().get('last-round')
    txinfo = client.pending_transaction_info(txid)
    while not (txinfo.get('confirmed-round') and txinfo.get('confirmed-round') > 0):
        print("Waiting for confirmation...")
        last_round += 1
        client.status_after_block(last_round)
        txinfo = client.pending_transaction_info(txid)
    print(f"Transaction {txid} confirmed in round {txinfo.get('confirmed-round')}")

if __name__ == "__main__":
    deploy_app()
