from pyteal import *

def approval_program():
    # Global State
    # None really needed if we just use it as a vault controlled by the App Account

    # Operations
    on_creation = Approve()
    
    on_delete = Return(Txn.sender() == Global.creator_address())
    
    on_update = Return(Txn.sender() == Global.creator_address())
    
    # Withdraw Action: Only Creator (App Backend) can withdraw for now
    # In a full DAO, we would check Voting State here.
    amount = Btoi(Txn.application_args[1])
    recipient = Txn.accounts[1]
    
    withdraw = Seq([
        # Assert sender is creator
        Assert(Txn.sender() == Global.creator_address()),
        
        # Inner Transaction to send ALGO
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetFields({
            TxnField.type_enum: TxnType.Payment,
            TxnField.receiver: recipient,
            TxnField.amount: amount,
            TxnField.fee: Int(0) # Caller pays fees
        }),
        InnerTxnBuilder.Submit(),
        
        Approve()
    ])

    program = Cond(
        [Txn.application_id() == Int(0), on_creation],
        [Txn.on_completion() == OnComplete.DeleteApplication, on_delete],
        [Txn.on_completion() == OnComplete.UpdateApplication, on_update],
        [Txn.on_completion() == OnComplete.OptIn, Approve()],
        [Txn.on_completion() == OnComplete.CloseOut, Approve()],
        [Txn.on_completion() == OnComplete.NoOp, Cond(
            [Txn.application_args[0] == Bytes("withdraw"), withdraw]
        )]
    )

    return compileTeal(program, Mode.Application, version=6)

def clear_state_program():
    return compileTeal(Approve(), Mode.Application, version=6)
