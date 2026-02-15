from algorand.connect import get_private_key_and_address, get_client
from algosdk import account, mnemonic

print("--- DEBUGGING CONNECTION ---")
pk, addr = get_private_key_and_address()
print(f"Address from connect.py: {addr}")

# Check if there is an env var overriding it?
import os
print(f"ALGO_MNEMONIC env var: {os.environ.get('ALGO_MNEMONIC')}")

# Manually derive from the mnemonic seen in file
mnemonic_str = "earth math flame often example online dentist foot forward debate unique imitate know board adapt describe usual come orphan pass hand sauce unable abandon plastic"
manual_pk = mnemonic.to_private_key(mnemonic_str)
manual_addr = account.address_from_private_key(manual_pk)
print(f"Manual derivation from hardcoded mnemonic: {manual_addr}")

if addr != manual_addr:
    print("WARNING: Address mismatch! effective address != hardcoded address")
else:
    print("Address match confirmed.")

print("--- END DEBUG ---")
