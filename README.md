# ArchEthic SDK for Python
This repo aims to provide a Python SDK for the ArchEthic project.<br>
It is based on the [official javascript sdk](https://github.com/archethic-foundation/libjs).
## Installation

```pip install archethic```

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
- [x] ec_encrypt() 
- [x] aes_encrypt()

### Transaction building
- [x] create TransactionBuilder class (TB)
- [x] TB.set_code()
- [x] TB.set_content()
- [x] TB.add_ownership()
- [x] TB.add_UCO_transfer()
- [x] TB.add_TOKEN_transfer()
- [x] TB.add_recipient()
- [x] TB.build()
- [x] TB.origin_sign()
- [x] TB.toJSON()
- [x] Interacting with other signer
  - [x] TB.previous_signature_payload()
  - [x] TB.set_previous_signature_and_previous_public_key()
  - [x] TB.set_address()
  - [x] TB.origin_signature_payload()
  - [x] TB.set_origin_sign()

### Remote Endpoint calls
- [ ] addOriginKey()
- [x] TB.send_transaction()
- [ ] wait_confirmations()
- [x] get_transaction_index()
- [ ] get_storage_nonce_public_key()
- [ ] get_transaction_fee()
- [ ] get_transaction_ownerships()

### Keychain / Wallet management
comming soon
