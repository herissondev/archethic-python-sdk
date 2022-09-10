import archethic
import json

#
seed = 'loizefozijeofizejfoizjfeoij'

api = archethic.Api('https://mainnet.archethic.net')


token = {
  "supply": archethic.to_big_int(1000000) ,
  "type": "fungible",
  "symbol": "TEST",
  "name": "TEST",
  "properties": []
}

tx = archethic.TransactionBuilder('token')
tx.set_content(json.dumps(token))

tx.build(seed, api.get_transaction_index(archethic.derive_address(seed, 0)))
tx.origin_sign(archethic.ORIGIN_PRIVATE_KEY)

print(api.send_tx(tx))