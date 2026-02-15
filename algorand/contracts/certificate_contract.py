from pyteal import *

def approval_program():
    # Only the creator can add certificates
    is_creator = Txn.sender() == Global.creator_address()
    
    # helper to check if box exists
    # Command handling
    command = Txn.application_args[0]

    add_certificate = Seq([
        # Verify sender is creator
        Assert(is_creator),
        
        # Verify arguments: command, hash, metadata
        Assert(Txn.application_args.length() == Int(3)),
        
        # Write to box (Name=Hash, Value=Metadata)
        App.box_put(Txn.application_args[1], Txn.application_args[2]),
        
        # Log success
        Log(Concat(Bytes("Added: "), Txn.application_args[1])),
        Return(Int(1))
    ])

    delete_certificate = Seq([
        # Verify sender is creator
        Assert(is_creator),

        # Verify arguments: command, hash
        Assert(Txn.application_args.length() == Int(2)),

        # Delete box
        Assert(App.box_delete(Txn.application_args[1])),

        # Log success
        Log(Concat(Bytes("Deleted: "), Txn.application_args[1])),
        Return(Int(1))
    ])

    handle_noop = Cond(
        [command == Bytes("add"), add_certificate],
        [command == Bytes("delete"), delete_certificate]
    )

    return compileTeal(
        Cond(
            [Txn.application_id() == Int(0), Return(Int(1))],
            [Txn.on_completion() == OnComplete.DeleteApplication, Return(is_creator)],
            [Txn.on_completion() == OnComplete.UpdateApplication, Return(is_creator)],
            [Txn.on_completion() == OnComplete.CloseOut, Return(Int(1))],
            [Txn.on_completion() == OnComplete.OptIn, Return(Int(1))],
            [Txn.on_completion() == OnComplete.NoOp, handle_noop]
        ),
        Mode.Application,
        version=8
    )

def clear_state_program():
    return compileTeal(Return(Int(1)), Mode.Application, version=8)

if __name__ == "__main__":
    with open("certificate_contract.teal", "w") as f:
        f.write(approval_program())
    with open("certificate_clear.teal", "w") as f:
        f.write(clear_state_program())
