from archethic.keychain import Keychain, key_to_jwk
from archethic import crypto
from archethic.transaction_builder import TransactionBuilder


def test_keychain_encode():
    keychain = Keychain("myseed")
    expected_binary = (
        bytearray([0, 0, 0, 1])
        + bytearray([6])
        + "myseed".encode()
        + bytearray([1])
        + bytearray([3])
        + "uco".encode()
        + bytearray([10])
        + "m/650'/0/0".encode()
        + bytearray([0])
        + bytearray([0])
    )
    assert keychain.encode() == expected_binary


def test_keychain_to_did():
    seed = "abcdefghijklmnopqrstuvwxyz"
    keychain = Keychain(seed)
    private_key, public_key = keychain.derive_keypair("uco", 0)
    address_hex = crypto.derive_address(seed, 0)

    did = keychain.to_did()
    id = did["id"]
    verification_methods = did["verificationMethod"]

    assert id == f"did:archethic:{address_hex}"

    expected = [
        {
            "id": f"did:archethic:{address_hex}#uco",
            "type": "JsonWebKey2020",
            "publicKeyJwk": key_to_jwk(public_key, "uco"),
            "controller": f"did:archethic:{address_hex}",
        }
    ]

    assert expected == verification_methods


def test_build_transaction_keychain():
    keychain = Keychain("seed")

    tx = TransactionBuilder("transfer")
    tx.add_uco_transfer(
        "0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646", 10
    )
    tx = keychain.build_tx(tx, "uco", 0)
    sk, pk = keychain.derive_keypair("uco")
    address = keychain.derive_address("uco", 1)

    assert tx.address == address
    assert tx.previous_public_key == bytes.fromhex(pk)
    assert (
        crypto.verify(
            tx.previous_signature,
            tx.previous_signature_payload(),
            tx.previous_public_key,
        )
        is True
    )
