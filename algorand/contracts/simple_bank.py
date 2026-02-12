from pyteal import *

def approval_program():
    on_creation = Seq([
        App.globalPut(Bytes("Creator"), Txn.sender()),
        Assert(Txn.application_args.length() == Int(0)),
        Return(Int(1))
    ])

    is_creator = Txn.sender() == App.globalGet(Bytes("Creator"))

    on_closeout = Return(Int(1))
    on_optin = Return(Int(1))

    # Deposit: User sends ALGO to the contract account
    # We expect a payment transaction in the same group
    deposit = Seq([
        # Verify the payment transaction
        Assert(Gtxn[0].type_enum() == TxnType.Payment),
        Assert(Gtxn[0].receiver() == Global.current_application_address()),
        Assert(Gtxn[0].amount() > Int(0)),
        Assert(Txn.group_index() == Int(1)), # Application call is 2nd transaction
        
        # Log the deposit
        Log(Concat(Bytes("Deposit: "), Itob(Gtxn[0].amount()))),
        Return(Int(1))
    ])

    # Withdraw: Contract sends ALGO to the user
    # Args: ["withdraw", amount]
    withdraw_amount = Btoi(Txn.application_args[1])
    withdraw = Seq([
        Assert(Txn.application_args.length() == Int(2)),
        Assert(withdraw_amount > Int(0)),
        # Only creator can withdraw for this simple demo, or use local state for user balances
        # For simplicity in this hackathon demo, let's allow anyone to withdraw if they are the creator (admin)
        Assert(is_creator), 
        
        # Inner Transaction to send ALGO
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetFields({
            TxnField.type_enum: TxnType.Payment,
            TxnField.receiver: Txn.sender(),
            TxnField.amount: withdraw_amount,
            TxnField.fee: Int(0) # LogicSig or App usually needs fee covering, but here contract pays via inner txn pooling if it has funds
        }),
        InnerTxnBuilder.Submit(),
        
        Log(Concat(Bytes("Withdraw: "), Itob(withdraw_amount))),
        Return(Int(1))
    ])

    handle_noop = Cond(
        [Txn.application_args[0] == Bytes("deposit"), deposit],
        [Txn.application_args[0] == Bytes("withdraw"), withdraw],
    )

    program = Cond(
        [Txn.application_id() == Int(0), on_creation],
        [Txn.on_completion() == OnComplete.OptIn, on_optin],
        [Txn.on_completion() == OnComplete.CloseOut, on_closeout],
        [Txn.on_completion() == OnComplete.UpdateApplication, Return(Int(is_creator))], # Only creator can update
        [Txn.on_completion() == OnComplete.DeleteApplication, Return(Int(is_creator))], # Only creator can delete
        [Txn.on_completion() == OnComplete.NoOp, handle_noop]
    )

    return compileTeal(program, Mode.Application, version=6)

def clear_state_program():
    return compileTeal(Return(Int(1)), Mode.Application, version=6)

if __name__ == "__main__":
    with open("simple_bank_approval.teal", "w") as f:
        f.write(approval_program())
    with open("simple_bank_clear.teal", "w") as f:
        f.write(clear_state_program())
