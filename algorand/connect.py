from algosdk import account, mnemonic
from algosdk.v2client.algod import AlgodClient

def get_client():
    algod_address = "https://testnet-api.algonode.cloud"
    algod_token = ""
    return AlgodClient(algod_token, algod_address)

def get_private_key_and_address():
    # REPLACE THIS MNEMONIC WITH YOUR FUNDED TESTNET ACCOUNT
    testnet_mnemonic = "earth math flame often example online dentist foot forward debate unique imitate know board adapt describe usual come orphan pass hand sauce unable abandon plastic"
    
    private_key = mnemonic.to_private_key(testnet_mnemonic)
    address = account.address_from_private_key(private_key)
    return private_key, address
