from algosdk.v2client import algod

algod_client = algod.AlgodClient(
    "",
    "https://testnet-api.algonode.cloud"
)

status = algod_client.status()
print(status)
