import archethic

api = archethic.Api('http://localhost:4000')
keychain = api.get_keychain('popo')
print(keychain.services)