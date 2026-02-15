from algorand.connect import get_private_key_and_address

_, address = get_private_key_and_address()
print(f"\nYour Testnet Address:\n{address}\n")
print("Please fund this address using a Testnet Dispenser: https://dispenser.testnet.aws.algodev.network/")
