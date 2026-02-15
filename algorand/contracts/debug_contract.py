from pyteal import *

def approval_program():
    add = Seq([
        App.box_put(Txn.application_args[1], Txn.application_args[2]),
        Approve()
    ])
    
    verify = Seq([
        App.box_length(Txn.application_args[1]),
        Approve()
    ])

    block = Cond(
        [Txn.application_args[0] == Bytes("add"), add],
        [Txn.application_args[0] == Bytes("verify"), verify] 
    )

    return compileTeal(block, Mode.Application, version=8)

if __name__ == "__main__":
    print(approval_program())
