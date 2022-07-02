import json
from archethic import crypto, utils
from typing import Union

VERSION = 1

TX_TYPES = {
    # User based transaction types
    "keychain_access": 254,
    "keychain": 255,
    "transfer": 253,
    "hosting": 252,
    "token": 251,
    # Network based transaction types
    "code_proposal": 7,
    "code_approval": 8
}


class TransactionBuilder:

    def __init__(self, tx_type: str) -> None:
        """
        Create a new instance of the transaction builder by specifying firstly the type of transaction :param
        tx_type:  Transaction type ("keychain_access", "keychain", "transfer", "hosting", "code_proposal",
        "code_approval", "token")
        """
        self.origin_signature: bytes = bytes()
        self.address: bytes = bytes()
        self.previous_public_key: bytes = bytes()
        self.previous_signature: bytes = bytes()
        assert tx_type in TX_TYPES, "Invalid transaction type. \n Transaction type must be 'transfer', 'hosting', " \
                                    "'keychain_access', 'keychain',  'token', 'code_proposal', 'code_approval' "

        self.version = VERSION
        self.tx_type = tx_type
        self.data = {
            "content": bytes(),
            "code": bytes(),
            "ownerships": [],
            "ledger": {
                "uco": {
                    "transfers": [],
                },
                "token": {
                    "transfers": [],
                },
            },
            "recipients": [],
        }

    def set_code(self, code: str) -> None:
        """
        Add smart contract code to the transcation
        :param code: The code of the transaction
        """
        isinstance(code, str), "Code must be string"
        self.data["code"] = code.encode()

    def set_content(self, content: Union[str, bytes]) -> None:
        """
        Add content to the transaction
        :param content: The content of the transaction
        """
        if isinstance(content, str):
            self.data["content"] = content.encode()
        elif isinstance(content, bytes):
            self.data["content"] = content
        else:
            raise TypeError("Content must be string or bytes")
        return

    def add_ownership(self, secret_key: Union[str, bytes], authorized_keys: list) -> None:
        """
        Add an ownership with a secret and its authorized public keys to the transaction
        :param secret_key: The secret key of the ownership (str or bytes)
        :param authorized_keys: The authorized public keys of the ownership
        """
        if isinstance(secret_key, str):
            if utils.is_hex(secret_key):
                secret_key = bytes.fromhex(secret_key)
            else:
                secret_key = secret_key.encode()
        elif isinstance(secret_key, bytes):
            pass
        else:
            raise TypeError("Secret key must be string or bytes")

        isinstance(authorized_keys, list), "Authorized keys must be list"

        new_authorized_keys = []
        for (public_key, encrypted_secret_key) in authorized_keys:

            if isinstance(public_key, str):
                if not utils.is_hex(public_key):
                    raise ValueError("Public key must be hex string")
                else:
                    public_key = bytes.fromhex(public_key)
            elif isinstance(public_key, bytes):
                pass
            else:
                raise TypeError("Public key must be string or bytes")

            if isinstance(encrypted_secret_key, str):
                if not utils.is_hex(encrypted_secret_key):
                    raise ValueError("Encrypted secret key must be hex string")
                else:
                    encrypted_secret_key = bytes.fromhex(encrypted_secret_key)
            elif isinstance(encrypted_secret_key, bytes):
                pass
            else:
                raise TypeError("Encrypted secret key must be hex string or bytes")

            new_authorized_keys.append(
                {
                    "publicKey": public_key,
                    "encryptedSecretKey": encrypted_secret_key,
                }
            )

        self.data["ownerships"].append({"secret": secret_key, "authorized_keys": new_authorized_keys})
        return

    def add_uco_transfer(self, send_to: Union[str, bytes], amount: float):
        """
        Add a UCO transfer to the transaction
        :param send_to: The public key of the receiver
        :param amount: The amount of UCO to send
        """
        if isinstance(send_to, str):
            if not utils.is_hex(send_to):
                raise ValueError("Public key must be hex string")
            else:
                send_to = bytes.fromhex(send_to)
        elif isinstance(send_to, bytes):
            pass
        else:
            raise TypeError("Public key must be string or bytes")

        isinstance(amount, float or int), "Amount must be float or int"
        assert amount > 0, "Amount must be greater than 0"

        self.data["ledger"]["uco"]["transfers"].append({"to": send_to, "amount": utils.to_big_int(amount)})
        return

    def add_token_transfer(self, send_to: Union[str, bytes], amount: float, token_adress: Union[str, bytes], token_id: int):
        """
        Add a token transfer to the transaction
        :param send_to: The public key of the receiver
        :param amount: The amount of tokens to send
        :param token_adress: The token address
        :param token_id: The token id
        """

        if isinstance(send_to, str):
            if not utils.is_hex(send_to):
                raise ValueError("Public key must be hex string")
            else:
                send_to = bytes.fromhex(send_to)
        elif isinstance(send_to, bytes):
            pass
        else:
            raise TypeError("Public key must be string or bytes")

        isinstance(amount, float or int), "Amount must be float or int"
        assert amount > 0, "Amount must be greater than 0"

        if isinstance(token_adress, str):
            if not utils.is_hex(token_adress):
                raise ValueError("Token address must be hex string")
            else:
                token_adress = bytes.fromhex(token_adress)
        elif isinstance(token_adress, bytes):
            pass
        else:
            raise TypeError("Token address must be string or bytes")

        isinstance(token_id, int), "Token id must be int"
        assert token_id >= 0, "Token id must be greater or equal to 0"

        self.data["ledger"]["token"]["transfers"].append({"to": send_to, "amount": utils.to_big_int(amount), "token": token_adress, "token_id": token_id})
        return

    def add_recipient(self, send_to: Union[str, bytes]):
        """
        Add a recipient to the transaction
        :param send_to: The public key of the receiver
        """
        if isinstance(send_to, str):
            if not utils.is_hex(send_to):
                raise ValueError("Public key must be hex string")
            else:
                send_to = bytes.fromhex(send_to)
        elif isinstance(send_to, bytes):
            pass
        else:
            raise TypeError("Public key must be string or bytes")

        self.data["recipients"].append(send_to)
        return

    def set_previous_signature_and_previous_public_key(self, signature: Union[str, bytes], public_key: Union[str, bytes]) -> None:
        """
        Set the transaction builder with Previous Publickey and Previous Signature
        :param signature: The previous signature of the transaction
        :param public_key: The previous public key of the transaction
        """
        if isinstance(signature, str):
            if not utils.is_hex(signature):
                raise ValueError("Signature must be hex string")
            else:
                signature = bytes.fromhex(signature)
        elif isinstance(signature, bytes):
            pass
        else:
            raise TypeError("Signature must be string or bytes")

        if isinstance(public_key, str):
            if not utils.is_hex(public_key):
                raise ValueError("Public key must be hex string")
            else:
                public_key = bytes.fromhex(public_key)
        elif isinstance(public_key, bytes):
            pass
        else:
            raise TypeError("Public key must be string or bytes")

        self.previous_public_key = public_key
        self.previous_signature = signature
        return

    def set_address(self, address: Union[str, bytes]):
        """
        Set the address of the transaction
        :param address: The address of the transaction
        """
        if isinstance(address, str):
            if not utils.is_hex(address):
                raise ValueError("Address must be hex string")
            else:
                address = bytes.fromhex(address)
        elif isinstance(address, bytes):
            pass
        else:
            raise TypeError("Address must be string or bytes")

        self.address = address
        return

    def build(self, seed: Union[str, bytes], index: int, curve: str = "ed25519", hash_algo: str = "sha256") -> None:
        private_key, public_key = crypto.derive_keypair(seed, index, curve)
        address = crypto.derive_address(seed, index+1, curve, hash_algo)
        self.set_address(address)
        self.previous_public_key = bytes.fromhex(public_key)

        payload_for_previous_signature = self.previous_signature_payload()

        self.previous_signature = crypto.sign(payload_for_previous_signature, private_key)
        return

    def origin_sign(self, private_key: Union[str, bytes]) -> None:
        """
        Sign the transaction with an origin private key
        :param private_key: Origin Private Key (hexadecimal or binary buffer)
        """
        if isinstance(private_key, str):
            if not utils.is_hex(private_key):
                raise ValueError("Private key must be hex string")
            else:
                private_key = bytes.fromhex(private_key)
        elif isinstance(private_key, bytes):
            pass
        else:
            raise TypeError("Private key must be hex string or bytes")

        self.origin_signature = crypto.sign(self.origin_signature_payload(), private_key)
        return

    def previous_signature_payload(self):
        """
        Generate the payload for the previous signature by encoding address, type and data
        :return: The payload for the previous signature
        """
        buff_code_size = utils.int_to_32(len(self.data["content"]))
        print(f"buff_code_size : {buff_code_size}")

        content_size = len(self.data["content"])
        print(f"content_size : {content_size}")
        #if type(self.data["content"]) == bytearray ??
        buf_content_size = utils.int_to_32(content_size)
        print(f"buf_content_size : {buf_content_size}")

        ownerships_buffer = []

        for (secret, authorizedKeys) in self.data["ownerships"]:
            authorized_keys_buffer = [bytearray([len(authorizedKeys)])]
            for (publicKey, encryptedSecretKey) in authorizedKeys:
                authorized_keys_buffer.append(publicKey)
                authorized_keys_buffer.append(encryptedSecretKey)

            ownerships_buffer.append(
                utils.int_to_32(len(bytes(secret))) +
                secret +
                b''.join(authorized_keys_buffer)
            )

        uco_transfers_buffers = [transfer['to'] + utils.int_to_64(transfer['amount']) for transfer in self.data["ledger"]["uco"]["transfers"]]
        print(f"uco_transfers_buffers : {uco_transfers_buffers[0].hex()}")
        token_transfers_buffers = [transfer['token'] + transfer['to'] + utils.int_to_64(transfer['amount']) + bytearray([transfer['token_id']]) for transfer in self.data["ledger"]["token"]["transfers"]]

        return (
            utils.int_to_32(VERSION)
            + self.address
            + bytearray([TX_TYPES[self.tx_type]])
            + buff_code_size
            + self.data["code"]
            + buf_content_size
            + self.data["content"]
            + bytearray([len(self.data["ownerships"])])
            + b''.join(ownerships_buffer)
            + bytearray([len(self.data["ledger"]["uco"]["transfers"])])
            + b''.join(uco_transfers_buffers)
            + bytearray([len(self.data["ledger"]["token"]["transfers"])])
            + b''.join(token_transfers_buffers)
            + bytearray([len(self.data["recipients"])])
            + b''.join(self.data["recipients"])
        )

    def set_origin_sign(self, signature: Union[str, bytes]) -> None:
        """
        Set the origin signature of the transaction
        :param signature: The origin signature of the transaction
        """
        if isinstance(signature, str):
            if not utils.is_hex(signature):
                raise ValueError("Signature must be hex string")
            else:
                signature = bytes.fromhex(signature)
        elif isinstance(signature, bytes):
            pass
        else:
            raise TypeError("Signature must be string or bytes")

        self.origin_signature = signature
        return

    def origin_signature_payload(self):
        payload_for_previous_signature = self.previous_signature_payload()
        print(f"payload_for_previous_signature : {payload_for_previous_signature.hex()}")
        return (
            payload_for_previous_signature
            + self.previous_public_key
            + bytearray([len(self.previous_signature)])
            + self.previous_signature
        )

    def json(self):

        data =  {
            "version": VERSION,
            "address": self.address.hex(),
            "type": self.tx_type,
            "data": {
                "content": self.data["content"].hex(),
                "code": self.data["code"].decode("utf-8"),
                "ownerships": [{"secret": secret.hex(), "authorizedKeys": [{"publicKey": publicKey.hex(), "encryptedSecretKey": encryptedSecretKey.hex()} for (publicKey, encryptedSecretKey) in authorizedKeys]} for (secret, authorizedKeys) in self.data["ownerships"]],
                "ledger": {
                    "uco": {
                        "transfers": [{"to": transfer["to"].hex(), "amount": transfer["amount"]} for transfer in self.data["ledger"]["uco"]["transfers"]]
                    },
                    "token": {
                        "transfers": [{"to": transfer["to"].hex(), "token": transfer["token"].hex(),  "amount": transfer["amount"], "token_id": transfer["token_id"]} for transfer in self.data["ledger"]["token"]["transfers"]]
                    }
                },
                "recipients": [recipient.hex() for recipient in self.data["recipients"]],

            },
            "previousPublicKey": self.previous_public_key.hex(),
            "previousSignature": self.previous_signature.hex(),
            "originSignature": self.origin_signature.hex()
        }

        return json.dumps(data)




