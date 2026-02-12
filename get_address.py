from algosdk import account, mnemonic

def get_address():
    testnet_mnemonic = "earth math flame often example online dentist foot forward debate unique imitate know board adapt describe usual come orphan pass hand sauce unable abandon plastic"
    private_key = mnemonic.to_private_key(testnet_mnemonic)
    address = account.address_from_private_key(private_key)
    print(f"Address: {address}")

if __name__ == "__main__":
    get_address()
