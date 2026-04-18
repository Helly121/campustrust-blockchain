import os
import sqlite3
import datetime
from algorand.advanced_features import mint_nft
from algorand.connect import get_client, get_private_key_and_address
from algosdk.transaction import AssetTransferTxn
from utils.rewards import opt_in_asset

def get_db_connection():
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database/campus.db')
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn

def issue_badge(user_id, issuer_id, badge_name, description, image_url, group_id=None):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        conn.close()
        return {"success": False, "error": "User not found."}
        
    has_wallet = bool(user['wallet_address'] and user['wallet_mnemonic'])
    
    # 1. Mint the NFT from the platform (creator) wallet
    # Usually unit names are 8 max chars. Let's use a standard prefix.
    unit_name = "CBADGE" 
    
    mint_res = mint_nft(unit_name, badge_name[:32], image_url)
    if not mint_res['success']:
        conn.close()
        return mint_res
    
    asset_id = mint_res['asset_id']
    tx_id = mint_res['tx_id']
    
    # 2. Optional: Transfer to user if they have a wallet
    if has_wallet:
        opt_res = opt_in_asset(user['wallet_mnemonic'], asset_id)
        if opt_res:
            client = get_client()
            private_key, sender_address = get_private_key_and_address()
            params = client.suggested_params()
            
            txn = AssetTransferTxn(
                sender=sender_address,
                sp=params,
                receiver=user['wallet_address'],
                amt=1,  # It's an NFT, so total supply is 1
                index=asset_id
            )
            
            try:
                signed_txn = txn.sign(private_key)
                transfer_txid = client.send_transaction(signed_txn)
            except Exception as e:
                print(f"Failed to transfer asset to user {user_id}: {e}")
                # We won't hard fail if transfer fails, they still earned it in DB
    
    # 4. Save to database
    try:
        issue_date = datetime.datetime.now().isoformat()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO digital_badges 
                         (user_id, issuer_id, group_id, badge_name, description, asset_id, tx_id, image_url, issue_date)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (user_id, issuer_id, group_id, badge_name, description, asset_id, tx_id, image_url, issue_date))
        conn.commit()
    except Exception as e:
        conn.close()
        return {"success": False, "error": f"Failed to save badge to database: {str(e)}"}
        
    conn.close()
    return {"success": True, "asset_id": asset_id, "tx_id": tx_id}
