import archethic

seed = 'thisismyprivatekey'
origin = archethic.ORIGIN_PRIVATE_KEY
api = archethic.Api('http://localhost:4000')

sk, pk = archethic.derive_keypair(seed, 0)
keychain_seed = archethic.random_secret_key()
keychain_tx = archethic.Keychain.new_keychain_transaction(keychain_seed, [pk], origin)

access_keychain_tx = archethic.Keychain.new_access_keychain_transaction(seed, keychain_tx.address, origin)

print(api.send_tx(keychain_tx))
print(api.send_tx(access_keychain_tx))

