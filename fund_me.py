from algorand.connect import get_private_key_and_address
from algosdk import account, mnemonic

try:
    private_key, address = get_private_key_and_address()
    print(f"\nExample App Wallet Address: {address}")
    print(f"\nTo fix the 'transaction failed' error, you need to fund this address with Testnet ALGOs.")
    print(f"1. Go to: https://dispenser.testnet.aws.algodev.network/")
    print(f"2. Paste the address above")
    print(f"3. Click 'Dispense'")
    print(f"4. Wait a few seconds and try uploading again.\n")
except Exception as e:
    print(f"Error reading mnemonic: {e}")
