import archethic

# make sure you have funds in your account
seed = 'myseed'
seed_address = archethic.derive_address(seed, 0)

origin = archethic.ORIGIN_PRIVATE_KEY

api = archethic.Api('http://localhost:4000')
ref_seed_index = api.get_transaction_index(seed_address)

receiver_address = archethic.derive_address('receiver', 0)

transaction = archethic.TransactionBuilder('transfer')
transaction.add_uco_transfer(receiver_address, 10)
transaction.build(seed, ref_seed_index)
transaction.origin_sign(origin)

fees = api.get_transaction_fee(transaction)

print(f"UCO Fees: {fees['fee']}")
if input('Send transaction? (y/n) \n') == 'y':
    print(api.send_tx(transaction))

