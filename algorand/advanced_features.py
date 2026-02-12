from algosdk import transaction, account, mnemonic
from algosdk.v2client import algod, indexer
from algosdk.transaction import (
    PaymentTxn, AssetConfigTxn, AssetTransferTxn, 
    ApplicationCreateTxn, ApplicationCallTxn, StateSchema, LogicSig
)
import base64
from .connect import get_client, get_private_key_and_address
from .store_hash import wait_for_confirmation

def get_indexer_client():
    # Helper to get indexer client (assuming sandbox/local or testnet defaults)
    # Adjust headers/address as needed for the user's environment
    # For Testnet via AlgoNode (common free tier):
    indexer_token = ""
    # Use a reliable public indexer
    indexer_address = "https://testnet-idx.algonode.cloud"
    headers = {'User-Agent': 'py-algorand-sdk'}
    return indexer.IndexerClient(indexer_token, indexer_address, headers)

def get_contract_history(app_id):
    """Fetch recent history for a simple bank contract."""
    try:
        client = get_indexer_client()
        from algosdk.logic import get_application_address
        app_addr = get_application_address(app_id)
        
        # Search for transactions involving the app address
        # Note: In production/sandbox, ensure indexer is reachable.
        response = client.search_transactions_by_address(app_addr, limit=10)
        txns = response.get("transactions", [])
        
        history = []
        for txn in txns:
            txtype = txn.get("tx-type")
            sender = txn.get("sender")
            
            if txtype == "pay":
                pay = txn.get("payment-transaction", {})
                amt = pay.get("amount", 0) / 1_000_000
                rcv = pay.get("receiver")
                
                action = "Unknown"
                if rcv == app_addr:
                    action = "Deposit"
                elif sender == app_addr:
                    action = "Withdrawal"
                
                history.append({
                    "round": txn.get("confirmed-round"),
                    "tx_id": txn.get("id"),
                    "action": action,
                    "amount": amt,
                    "user": sender if action == "Deposit" else rcv
                })
        
        return {"success": True, "history": history}
    except Exception as e:
        return {"success": False, "error": str(e)}

def send_algo_payment(receiver_addr, amount_algo, note_text):
    """Send ALGO payment."""
    client = get_client()
    private_key, sender_address = get_private_key_and_address()
    
    params = client.suggested_params()
    amount_microalgo = int(float(amount_algo) * 1_000_000)
    
    txn = PaymentTxn(
        sender=sender_address,
        sp=params,
        receiver=receiver_addr,
        amt=amount_microalgo,
        note=note_text.encode()
    )
    
    try:
        signed_txn = txn.sign(private_key)
        txid = client.send_transaction(signed_txn)
        confirmed_round = wait_for_confirmation(client, txid)
        return {"success": True, "tx_id": txid, "confirmed_round": confirmed_round}
    except Exception as e:
        return {"success": False, "error": str(e)}

def create_asa(unit_name, asset_name, total, decimals, url=None):
    """Create a Fungible Token (ASA)."""
    client = get_client()
    private_key, sender_address = get_private_key_and_address()
    
    params = client.suggested_params()
    
    txn = AssetConfigTxn(
        sender=sender_address,
        sp=params,
        total=int(total),
        decimals=int(decimals),
        default_frozen=False,
        unit_name=unit_name,
        asset_name=asset_name,
        manager=sender_address,
        reserve=sender_address,
        freeze=sender_address,
        clawback=sender_address,
        url=url
    )
    
    try:
        signed_txn = txn.sign(private_key)
        txid = client.send_transaction(signed_txn)
        wait_for_confirmation(client, txid)
        
        # Get asset ID
        ptx = client.pending_transaction_info(txid)
        asset_id = ptx["asset-index"]
        
        return {"success": True, "tx_id": txid, "asset_id": asset_id}
    except Exception as e:
        return {"success": False, "error": str(e)}

def mint_nft(unit_name, asset_name, ipfs_url, ipfs_metadata_hash_str=None):
    """Mint an NFT (ASA with total=1, decimals=0)."""
    client = get_client()
    private_key, sender_address = get_private_key_and_address()
    
    params = client.suggested_params()
    
    # Handle metadata hash if provided (must be 32 bytes)
    # If string is hex, decode it. If generic string, maybe hash it?
    # Standards usually expect 32 bytes for asset_metadata_hash provided as bytes.
    # For this demo, let's assume it's optional or handled simply.
    
    txn = AssetConfigTxn(
        sender=sender_address,
        sp=params,
        total=1,
        decimals=0,
        default_frozen=False,
        unit_name=unit_name,
        asset_name=asset_name,
        manager=sender_address,
        reserve=sender_address,
        freeze=sender_address,
        clawback=sender_address,
        url=ipfs_url
        # asset_metadata_hash=... 
    )
    
    try:
        signed_txn = txn.sign(private_key)
        txid = client.send_transaction(signed_txn)
        wait_for_confirmation(client, txid)
        
        ptx = client.pending_transaction_info(txid)
        asset_id = ptx["asset-index"]
        
        return {"success": True, "tx_id": txid, "asset_id": asset_id}
    except Exception as e:
        return {"success": False, "error": str(e)}

def compile_program(client, source_code):
    compile_response = client.compile(source_code)
    return base64.b64decode(compile_response['result'])

def deploy_smart_contract(approval_teal, clear_teal):
    """Deploy a stateful smart contract."""
    client = get_client()
    private_key, sender_address = get_private_key_and_address()
    
    try:
        approval_program = compile_program(client, approval_teal)
        clear_program = compile_program(client, clear_teal)
        
        # Define schema (adjust as needed for the generic/bank contract)
        # Bank needs: Global: Creator(bytes) -> 1 Bytes slice.
        # Local: None for now.
        global_schema = StateSchema(num_uints=0, num_bytes=1)
        local_schema = StateSchema(num_uints=0, num_bytes=0)
        
        params = client.suggested_params()
        
        txn = ApplicationCreateTxn(
            sender=sender_address,
            sp=params,
            on_complete=transaction.OnComplete.NoOpOC,
            approval_program=approval_program,
            clear_program=clear_program,
            global_schema=global_schema,
            local_schema=local_schema
        )
        
        signed_txn = txn.sign(private_key)
        txid = client.send_transaction(signed_txn)
        wait_for_confirmation(client, txid)
        
        ptx = client.pending_transaction_info(txid)
        app_id = ptx["application-index"]
        
        return {"success": True, "tx_id": txid, "app_id": app_id}
    except Exception as e:
        return {"success": False, "error": str(e)}

def fund_app_account(app_id, amount_algo=1.0):
    """Helper to fund the app account so it can do inner transactions."""
    from algosdk.logic import get_application_address
    app_addr = get_application_address(app_id)
    return send_algo_payment(app_addr, amount_algo, "Funding App")

def call_bank_deposit(app_id, amount_algo):
    """Call 'deposit' on the bank contract."""
    client = get_client()
    private_key, sender_address = get_private_key_and_address()
    params = client.suggested_params()
    
    # 1. Payment Txn
    amount_microalgo = int(float(amount_algo) * 1_000_000)
    from algosdk.logic import get_application_address
    app_addr = get_application_address(app_id)
    
    pay_txn = PaymentTxn(sender_address, params, app_addr, amount_microalgo)
    
    # 2. App Call Txn
    app_args = ["deposit"]
    app_txn = ApplicationCallTxn(sender_address, params, app_id, transaction.OnComplete.NoOpOC, app_args=app_args)
    
    # Group them using assign_group_id
    transaction.assign_group_id([pay_txn, app_txn])
    
    try:
        signed_pay = pay_txn.sign(private_key)
        signed_app = app_txn.sign(private_key)
        
        txid = client.send_transactions([signed_pay, signed_app])
        wait_for_confirmation(client, txid)
        
        return {"success": True, "tx_id": txid}
    except Exception as e:
        return {"success": False, "error": str(e)}

def call_bank_withdraw(app_id, amount_algo):
    """Call 'withdraw' on the bank contract."""
    client = get_client()
    private_key, sender_address = get_private_key_and_address()
    params = client.suggested_params()
    
    # Increase fees for inner txn?
    # Simple bank assumes it covers it or we pool fees.
    # Let's double fee on the outer txn to cover inner if needed, or rely on pooling.
    params.fee = 2000 
    
    amount_microalgo = int(float(amount_algo) * 1_000_000)
    app_args = ["withdraw", amount_microalgo]
    
    txn = ApplicationCallTxn(sender_address, params, app_id, transaction.OnComplete.NoOpOC, app_args=app_args)
    
    try:
        signed_txn = txn.sign(private_key)
        txid = client.send_transaction(signed_txn)
        wait_for_confirmation(client, txid)
        return {"success": True, "tx_id": txid}
    except Exception as e:
        return {"success": False, "error": str(e)}
