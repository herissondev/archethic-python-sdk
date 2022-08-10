import archethic
import json
seed = 'testooooo'
origin = archethic.ORIGIN_PRIVATE_KEY
api = archethic.Api('http://localhost:4000')

sk, pk = archethic.derive_keypair(seed, 0)
keychain_seed = archethic.random_secret_key()
print(type(keychain_seed))
keychain_tx = archethic.Keychain.new_keychain_transaction(keychain_seed, [pk], origin)

print(api.get_transaction_fee(keychain_tx))
print(keychain_tx.json())
if input('Send tx? (y/n)') == 'y':
    print(api.send_tx(keychain_tx))

#todo keyhain ne fonctionne pasaaaa