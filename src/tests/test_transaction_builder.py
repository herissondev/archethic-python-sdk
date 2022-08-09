from archethic.transaction_builder import TransactionBuilder
from archethic import crypto, utils
import json


def test_type():
    transaction = TransactionBuilder("transfer")
    isinstance(transaction, TransactionBuilder)


def test_set_code():
    transaction = TransactionBuilder("transfer")
    transaction.set_code("my smart contract code")
    assert transaction.data["code"].decode() == "my smart contract code"


def test_set_content():
    transaction = TransactionBuilder("transfer")
    transaction.set_content("my super content")
    assert transaction.data["content"].decode() == "my super content"


def test_add_ownership():
    transaction = TransactionBuilder("transfer")
    transaction.add_ownership(
        "00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88",
        [
            {
                "publicKey": "0001b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646",
                "encryptedSecretKey": "00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88",
            }
        ],
    )
    assert transaction.data["ownerships"][0]["secret"] == bytes.fromhex(
        "00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"
    )
    assert transaction.data["ownerships"][0]["authorizedKeys"] == [
        {
            "publicKey": bytes.fromhex(
                "0001b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"
            ),
            "encryptedSecretKey": bytes.fromhex(
                "00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"
            ),
        }
    ]


def test_add_uco_transfer():
    transaction = TransactionBuilder("transfer")
    transaction.add_uco_transfer(
        "0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646", 10.03
    )
    assert len(transaction.data["ledger"]["uco"]["transfers"]) == 1
    assert transaction.data["ledger"]["uco"]["transfers"][0]["to"] == bytes.fromhex(
        "0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"
    )
    assert transaction.data["ledger"]["uco"]["transfers"][0]["amount"] == 1003000000


# TODO test_add_token_transfer
def test_add_token_transfer():
    return True


def test_previous_signature_payload():
    code = """
    condition inherit: [
        uco_transferred: 0.020
    ]
    
    actions triggered by: transaction do
        set_type transfer
        add_uco_ledger  to: "000056E763190B28B4CF9AAF3324CF379F27DE9EF7850209FB59AA002D71BA09788A", amount: 0.020
    end
    """
    content = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec sit amet leo egestas, lobortis lectus a, dignissim orci."
    secret = "mysecret"

    transaction = TransactionBuilder("transfer")
    transaction.add_ownership(
        secret,
        [
            {
                "publicKey": "0001b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646",
                "encryptedSecretKey": "00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88",
            }
        ],
    )
    transaction.add_uco_transfer(
        "0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646", 0.2020
    )
    transaction.add_token_transfer(
        "0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646",
        100,
        "0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88",
        1,
    )
    transaction.set_code(code)
    transaction.set_content(content)
    transaction.add_recipient(
        "0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"
    )
    transaction.build("seed", 0, "P256")

    sk, pk = crypto.derive_keypair("seed", 0, "P256")
    previous_signature = crypto.sign(transaction.previous_signature_payload(), sk)

    payload = transaction.origin_signature_payload()

    expected_binary = (
        # version
        utils.int_to_32(1)
        + transaction.address
        + bytearray([253])
        +
        # code size
        utils.int_to_32(len(code))
        + code.encode()
        +
        # content size
        utils.int_to_32(len(content))
        + content.encode()
        +
        # Nb of byte to encode nb of ownerships
        bytearray([1])
        +
        # Nb of ownerships
        bytearray([1])
        +
        # Secret size
        utils.int_to_32(len(secret))
        + secret.encode()
        +
        # Nb of byte to encode nb of authorized keys
        bytearray([1])
        +
        # Nb of authorized keys
        bytearray([1])
        +
        # Authorized keys encoding
        bytes.fromhex(
            "0001b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"
        )
        + bytes.fromhex(
            "00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"
        )
        +
        # Nb of byte to encode nb of uco transfers
        bytearray([1])
        +
        # Nb of uco transfers
        bytearray([1])
        + bytes.fromhex(
            "0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"
        )
        + utils.int_to_64(utils.to_big_int(0.2020))
        +
        # Nb of byte to encode nb of Token transfers
        bytearray([1])
        +
        # Nb of Token transfers
        bytearray([1])
        + bytes.fromhex(
            "0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"
        )
        + bytes.fromhex(
            "0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"
        )
        + utils.int_to_64(utils.to_big_int(100))
        + bytearray([1])  # missing bytearray 0 ?
        +
        # Nb of byte to encode nb of recipients
        bytearray([1])
        +
        # Nb of recipients
        bytearray([1])
        + bytes.fromhex(
            "0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"
        )
        + bytes.fromhex(pk)
        + bytearray([len(previous_signature)])
        + previous_signature
    )
    assert len(payload) == len(expected_binary)
    assert payload == expected_binary


def test_origin_signature():
    sk, pk = crypto.derive_keypair("origin_seed", 0)
    tx = TransactionBuilder("transfer")
    tx.build("seed", 0)
    tx.origin_sign(sk)

    assert crypto.verify(tx.origin_signature, tx.origin_signature_payload(), pk) is True


def test_json():
    origin_keypair = crypto.derive_keypair("origin_seed", 0)
    transaction_keypair = crypto.derive_keypair("seed", 0)

    tx = TransactionBuilder("transfer")
    tx.add_uco_transfer(
        "0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646", 0.2193
    )
    tx.add_ownership(
        bytes(bytearray([0, 1, 2, 3, 4])),
        [
            {
                "publicKey": "0001b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646",
                "encryptedSecretKey": "00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88",
            }
        ],
    )
    tx.build("seed", 0)
    tx.origin_sign(origin_keypair[0])

    parsed_tx = json.loads(tx.json())

    previous_signature = crypto.sign(
        tx.previous_signature_payload(), transaction_keypair[0]
    )
    origin_signature = crypto.sign(tx.origin_signature_payload(), origin_keypair[0])

    assert parsed_tx["address"] == crypto.derive_address("seed", 1)
    assert parsed_tx["previousPublicKey"] == transaction_keypair[1]
    assert parsed_tx["previousSignature"] == previous_signature.hex()
    assert (
        parsed_tx["data"]["ownerships"][0]["secret"] == bytearray([0, 1, 2, 3, 4]).hex()
    )
    assert parsed_tx["data"]["ledger"]["uco"]["transfers"][0] == {
        "to": "0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646",
        "amount": utils.to_big_int(0.2193),
    }
    assert parsed_tx["data"]["ownerships"][0]["authorizedKeys"] == [
        {
            "publicKey": "0001b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646",
            "encryptedSecretKey": "00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88",
        }
    ]
    assert parsed_tx["originSignature"] == origin_signature.hex()
