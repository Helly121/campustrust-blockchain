from algorand.connect import get_client, get_private_key_and_address

client = get_client()
_, address = get_private_key_and_address()
info = client.account_info(address)
print(f"Address: {address}")
print(f"Balance: {info.get('amount')} microAlgos")
