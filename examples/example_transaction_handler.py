import archethic
import asyncio

async def main():
    # make sure you have funds in your account
    seed = 'zgrzrgezrgerg'
    seed_address = archethic.derive_address(seed, 0)

    origin = archethic.ORIGIN_PRIVATE_KEY

    api = archethic.Api('http://localhost:4000')
    #ref_seed_index = api.get_transaction_index(seed_address)

    receiver_address = archethic.derive_address('receiver', 0)

    transaction = archethic.TransactionBuilder('transfer')
    transaction.add_uco_transfer("00000f3ff5cdb8af62c10612147b50ffc2b7b1559e998f5a24784d2d0686b914e1f2", 1)
    transaction.build(seed, await api.get_transaction_index(seed_address))

    transaction.origin_sign(origin)

    fees = await api.get_transaction_fee(transaction)

    handler = api.create_transaction_handler()

    def printt(a,b):
        print(a)
        print(b)
    handler.on('confirmation',printt)


    print(f"UCO Fees: {fees['fee'] / (10**8)} ")
    if input('Send transaction? (y/n) \n') == 'y':
        print(await handler.send(transaction))




asyncio.run(main())