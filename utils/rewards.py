import os
import sqlite3
import json
from algorand.advanced_features import create_asa, send_algo_payment
from algorand.connect import get_client, get_private_key_and_address
from algosdk.transaction import AssetTransferTxn
from algosdk import account, mnemonic

# File to store system state (like Token ID)
STATE_FILE = 'system_state.json'
TOKEN_NAME = "CampusToken"
TOKEN_UNIT = "CAMPUS"

def get_db_connection():
    # Helper to connect to DB (duplicated from app.py for standalone utility use if needed)
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database/campus.db')
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_state(state):
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=4)

def ensure_campus_token():
    """
    Checks if Campus Token exists. If not, creates it.
    Returns the Asset ID.
    """
    state = load_state()
    asset_id = state.get('campus_token_id')
    
    if asset_id:
        return asset_id
    
    print(f"[{TOKEN_NAME}] Not found. Creating new Asset...")
    
    # Create the Asset
    result = create_asa(
        unit_name=TOKEN_UNIT,
        asset_name=TOKEN_NAME,
        total=1_000_000_000, # 1 Billion Supply
        decimals=0,          # Integers only for simplicity
        url="https://campustrust.edu/token"
    )
    
    if result['success']:
        asset_id = result['asset_id']
        state['campus_token_id'] = asset_id
        save_state(state)
        print(f"[{TOKEN_NAME}] Created successfully! Asset ID: {asset_id}")
        return asset_id
    else:
        print(f"[{TOKEN_NAME}] Creation Failed: {result['error']}")
        return None

def distribute_reward(user_id, amount, reason="Reward"):
    """
    Sends Campus Tokens to a user's wallet.
    Requires user to have opted-in (but for this demo, we might skip opt-in check logic complexity 
    or assume we abuse the creator address if it's custodial, OR better:
    Since we generate user wallets, we can auto-opt-in on creation).
    """
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    if not user or not user['wallet_address']:
        print(f"User {user_id} has no wallet. Cannot send reward.")
        return False
        
    receiver_addr = user['wallet_address']
    asset_id = ensure_campus_token()
    
    if not asset_id:
        return False
        
    client = get_client()
    private_key, sender_address = get_private_key_and_address()
    params = client.suggested_params()
    
    # Note: receiver must be opted-in. 
    # For this hackathon demo, we will try to send. If it fails due to opt-in, we just log it.
    
    txn = AssetTransferTxn(
        sender=sender_address,
        sp=params,
        receiver=receiver_addr,
        amt=amount,
        index=asset_id,
        note=reason.encode()
    )
    
    try:
        signed_txn = txn.sign(private_key)
        txid = client.send_transaction(signed_txn)
        # We process in background, so maybe don't wait for confirmation to keep UI fast?
        # But for reliability let's wait or return txid.
        return txid
    except Exception as e:
        print(f"Failed to send reward: {e}")
        return None

def generate_student_wallet():
    """
    Generates a new Algorand account.
    Returns (address, mnemonic).
    """
    private_key, address = account.generate_account()
    passphrase = mnemonic.from_private_key(private_key)
    return address, passphrase

def opt_in_asset(user_mnemonic, asset_id):
    """
    Opts a user into an asset.
    """
    try:
        updated_private_key = mnemonic.to_private_key(user_mnemonic)
        updated_address = account.address_from_private_key(updated_private_key)
        
        client = get_client()
        params = client.suggested_params()
        
        # Opt-in is a 0 amount transfer to self
        txn = AssetTransferTxn(
            sender=updated_address,
            sp=params,
            receiver=updated_address,
            amt=0,
            index=asset_id
        )
        
        signed_txn = txn.sign(updated_private_key)
        txid = client.send_transaction(signed_txn)
        return True
    except Exception as e:
        print(f"Opt-in failed: {e}")
        return False
