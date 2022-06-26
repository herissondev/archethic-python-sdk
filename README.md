# ArchEthic SDK for Python
This repo aims to provide a Python SDK for the ArchEthic project.<br>
It is based on the [official javascript sdk](https://github.com/archethic-foundation/libjs).
## Installation
Clone this repo with `git clone https://github.com/aime-risson/archethic-python-sdk.git` 

Install requirements with `pip install -r requirements.txt`

Finally, install the package with `python setup.py install`

## Contribution

Thank you for considering to help out with the source code. 
We welcome contributions from anyone and are grateful for even the smallest of improvement.

Please to follow this workflow:
1. Fork it!
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create new Pull Request


(copied from archethic-foundation)
## TODOs
### Utils
- [x] Implementation of utils

### Cryptographic functions
- [x] get_originKey()
- [x] derive_keypair()
- [x] derive_address()
- [ ] ec_encrypt() [link](https://codeahoy.com/learn/practicalcryptography/asymmetric-key-ciphers/ecies-example/)
- [ ] aes_encrypt()

### Transaction building
- [ ] create TransactionBuilder class (TB)
- [ ] TB.set_code()
- [ ] TB.set_content()
- [ ] TB.add_ownership()
- [ ] TB.add_UCO_transfer()
- [ ] TB.add_NFT_transfer()
- [ ] TB.add_recipient()
- [ ] TB.build()
- [ ] TB.origin_sign()
- [ ] TB.toJSON()
- [ ] Interacting with other signer
  - [ ] TB.previous_signature_payload()
  - [ ] TB.set_previous_signature_and_previous_public_key()
  - [ ] TB.set_address()
  - [ ] TB.origin_signature_payload()
  - [ ] TB.set_origin_sign()

### Remote Endpoint calls
- [ ] addOriginKey()
- [ ] TB.send_transaction()
- [ ] wait_confirmations()
- [ ] get_transaction_index()
- [ ] get_storage_nonce_public_key()
- [ ] get_transaction_fee()
- [ ] get_transaction_ownerships()

### Keychain / Wallet management
comming soon
