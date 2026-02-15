from algorand.connect import get_client, get_private_key_and_address
from algosdk.logic import get_application_address

def check_balances():
    client = get_client()
    _, creator_addr = get_private_key_and_address()
    
    app_id = 755556381
    app_addr = get_application_address(app_id)
    
    # Creator Balance
    try:
        creator_info = client.account_info(creator_addr)
        creator_bal = creator_info.get('amount') / 1_000_000
        print(f"Server Wallet (Creator) [{creator_addr}]: {creator_bal} ALGO")
    except Exception as e:
        print(f"Failed to get Creator info: {e}")

    # App Account Balance
    try:
        app_info = client.account_info(app_addr)
        app_bal = app_info.get('amount') / 1_000_000
        print(f"App Account [{app_addr}]: {app_bal} ALGO")
        print(f"  Min Balance Limit: {app_info.get('min-balance') / 1_000_000} ALGO")
    except Exception as e:
        print(f"Failed to get App info: {e}")

if __name__ == "__main__":
    check_balances()
