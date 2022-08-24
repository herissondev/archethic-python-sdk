import archethic
import json

#
seed = 'thisismyprivatekey'

api = archethic.Api('http://localhost:4000')

keychain = api.get_keychain(seed)
token = {
  "supply": archethic.to_big_int(1000000) ,
  "type": "fungible",
  "symbol": "TEST",
  "name": "TEST",
  "properties": []
}

tx = archethic.TransactionBuilder('token')
tx.set_content(json.dumps(token))

tx = keychain.build_tx(tx, 'uco', api.get_transaction_index(keychain.derive_address('uco').hex()))
tx.origin_sign(archethic.ORIGIN_PRIVATE_KEY)

print(api.send_tx(tx))