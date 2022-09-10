from archethic.transaction_builder import TransactionBuilder
from archethic.utils import int_to_32, int_to_64, uint8array_to_int, is_hex
from archethic.crypto import (
    generate_deterministic_keypair,
    derive_address,
    derive_keypair,
    hash_digest,
    get_curve_id,
    get_curve_name,
    get_hash_id,
    random_secret_key,
    ec_encrypt,
    aes_encrypt,
    get_hash_name,
    sign,
)
from typing import Union, Dict
import json
import hmac
import hashlib
import base64


KEYCHAIN_ORIGIN_ID = 0


class Keychain:
    def __init__(self, seed: Union[str, bytes], version: int = 1) -> None:
        """

        :param seed:
        """

        if isinstance(seed, bytes):
            pass

        elif isinstance(seed, str):
            seed = seed.encode()
        else:
            raise ValueError("Seed must be bytes or string")

        self.seed: bytes = seed
        self.version: int = version
        self.services: dict = {}

        self.add_service("uco", "m/650'/0/0")

    @classmethod
    def from_binary(cls, binary: bytes):
        """Return a keychain from a binary data"""
        pos = 0
        version, pos = read_bytes(binary, pos, 4)
        seed_length, pos = read_byte(binary, pos, 1)
        seed, pos = read_bytes(binary, pos, seed_length)
        service_count, pos = read_byte(binary, pos, 1)

        keychain = cls(seed, uint8array_to_int(version))

        for i in range(service_count):
            service_length, pos = read_byte(binary, pos, 1)
            service, pos = read_bytes(binary, pos, service_length)
            derivation_path_length, pos = read_byte(binary, pos, 1)
            derivation_path, pos = read_bytes(binary, pos, derivation_path_length)
            curve_id, pos = read_byte(binary, pos, 1)
            hash_id, pos = read_byte(binary, pos, 1)

            service_name = service.decode()
            derivation_path_name = derivation_path.decode()

            keychain.add_service(
                service_name,
                derivation_path_name,
                get_curve_name(curve_id),
                get_hash_name(hash_id),
            )

        return keychain

    @staticmethod
    def new_access_keychain_transaction(
        seed: Union[str, bytes],
        keychain_address: Union[str, bytes],
        origin_private_key: Union[str, bytes],
    ) -> TransactionBuilder:
        """
        Create a new access keychain and build a transaction.
        :param seed:
        :param keychain_address:
        :return:
        """
        # todo add assertion for all variables

        aes_key = random_secret_key()
        sk, pk = derive_keypair(seed, 0)

        encrypted_secret_key = ec_encrypt(aes_key, pk)

        authorized_keys = [
            {
                "publicKey": pk,
                "encryptedSecretKey": encrypted_secret_key,
            }
        ]

        tx = TransactionBuilder("keychain_access")
        tx.add_ownership(aes_encrypt(keychain_address, aes_key), authorized_keys)
        tx.build(seed, 0)
        tx.origin_sign(origin_private_key)
        return tx

    @staticmethod
    def new_keychain_transaction(
        seed: Union[str, bytes],
        authorized_public_keys: [],
        origin_private_key: Union[str, bytes],
    ) -> TransactionBuilder:
        """
        Creates a new keychain transaction
        """

        keychain = Keychain(seed)
        aes_key = random_secret_key()

        authorized_keys = []

        for key in authorized_public_keys:
            authorized_keys.append(
                {"publicKey": key, "encryptedSecretKey": ec_encrypt(aes_key, key)}
            )

        tx = TransactionBuilder("keychain")
        tx.set_content(json.dumps(keychain.to_did()))

        tx.add_ownership(aes_encrypt(keychain.encode(), aes_key), authorized_keys)
        tx.build(seed, 0)
        tx.origin_sign(origin_private_key)

        return tx

    def add_service(
        self,
        service_name: str,
        derivation_path,
        curve: str = "ed25519",
        hash_algo: str = "sha256",
    ) -> None:
        self.services[service_name] = {
            "derivationPath": derivation_path,
            "curve": curve,
            "hashAlgo": hash_algo,
        }

    def encode(self) -> bytes:

        service_buffer = []

        for service in self.services:
            _service = self.services[service]
            service_buffer.append(
                (
                    bytearray([len(_service)])
                    + service.encode()
                    + bytearray([len(_service["derivationPath"])])
                    + _service["derivationPath"].encode()
                    + bytearray([get_curve_id(_service["curve"])])
                    + bytearray([get_hash_id(_service["hashAlgo"])])
                )
            )

        return (
            int_to_32(self.version)
            + bytearray([len(self.seed)])
            + self.seed
            + bytearray([len(self.services.keys())])
            + b"".join(service_buffer)
        )

    def derive_keypair(self, service: str, index: int = 0):

        if not service in self.services:
            raise ValueError("Service doesn't exist in the keychain")

        _service = self.services[service]

        return derive_archethic_keypair(
            self.seed, _service["derivationPath"], index, _service["curve"]
        )

    def derive_address(self, service: str, index: int = 0):

        if service not in self.services:
            raise ValueError("Service doesn't exist in the keychain")

        _service = self.services[service]
        derivation_path = _service["derivationPath"]
        curve = _service["curve"]
        hash_algo = _service["hashAlgo"]

        sk, pk = derive_archethic_keypair(self.seed, derivation_path, index, curve)
        curve_id = get_curve_id(curve)

        hashed_public_key = hash_digest(pk, hash_algo)

        return bytes(bytearray([curve_id]) + bytearray(hashed_public_key))

    def build_tx(
        self, tx: TransactionBuilder, service: str, index: int
    ) -> TransactionBuilder:
        """
        Generate address, previousPublicKey, previousSignature of the transaction and serialize it using a custom binary
        protocol, based on the derivation path, curve and hash algo of the service given in param.
        :param tx: An instance of TransactionBuilder
        :param service: The service name to use for getting the derivation path, the curve and the hash algo
        :param index: The number of transactions in the chain, to generate the actual and the next public key
        :return: Return is the signed TransactionBuilder
        """
        sk, pk = self.derive_keypair(service, index)
        address = self.derive_address(service, index + 1)

        tx.set_address(bytes(address))

        payload_for_previous_signature = tx.previous_signature_payload()
        previous_signature = sign(payload_for_previous_signature, sk)

        tx.set_previous_signature_and_previous_public_key(previous_signature, pk)

        return tx

    def to_did(self) -> Dict[str, str]:
        """
        Returns a dictionary with the DID and the verification method
        """
        address_hex = derive_address(self.seed, 0)

        verification_methods = []
        authentications = []
        for service in self.services:
            derivationPath = self.services[service]["derivationPath"]
            curve = self.services[service]["curve"]

            purpose = derivationPath.split("/")[1].replace("'", "")

            if purpose == "650":
                sk, pk = derive_archethic_keypair(self.seed, derivationPath, 0, curve)
                verification_methods.append(
                    {
                        "id": f"did:archethic:{address_hex}#{service}",
                        "type": "JsonWebKey2020",
                        "publicKeyJwk": key_to_jwk(pk, service),
                        "controller": f"did:archethic:{address_hex}",
                    }
                )
                authentications.append(f"did:archethic:{address_hex}#{service}")

            else:
                raise ValueError(f"Purpose ' {purpose} ' is not yet supported")

        return {
            "@context": [
                "https://www.w3.org/ns/did/v1",
            ],
            "id": f"did:archethic:{address_hex}",
            "authentication": authentications,
            "verificationMethod": verification_methods,
        }


def derive_archethic_keypair(seed: bytes, derivation_path, index, curve="ed25519"):
    hashed_path = hashlib.sha256(
        replace_derivation_path_index(derivation_path, index).encode()
    ).digest()
    extended_seed = hmac.new(seed, hashed_path, "sha512").digest()[:32]
    return generate_deterministic_keypair(extended_seed, curve, KEYCHAIN_ORIGIN_ID)


def replace_derivation_path_index(path: str, index):
    path = path.split("/")
    path = path[:-1]
    path.append(f"{index}'")
    path = "/".join(path)
    return path


def key_to_jwk(publickey: Union[str, bytes], key_id: str) -> Dict[str, str]:

    if isinstance(publickey, str):
        publickey = bytes.fromhex(publickey)
    elif isinstance(publickey, bytes):
        pass
    else:
        raise ValueError("Publickey must be bytes or string")

    curve_id = publickey[0]
    key = publickey[2:]

    if curve_id == 0:
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": to_base64_url(key),
            "kid": key_id,
        }
    elif curve_id == 1:
        x = key[:16]
        y = key[16:]
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": to_base64_url(x),
            "y": to_base64_url(y),
            "kid": key_id,
        }
    elif curve_id == 1:
        x = key[:16]
        y = key[16:]
        return {
            "kty": "EC",
            "crv": "secp256k1",
            "x": to_base64_url(x),
            "y": to_base64_url(y),
            "kid": key_id,
        }
    else:
        raise ValueError("Curve not supported")


def to_base64_url(data: bytes or str) -> str:
    return base64.urlsafe_b64encode(data).replace(b"=", b"").decode()


def read_byte(binary: bytes, pos: int, size: int) -> (bytes, int):
    return binary[pos : pos + size][0], pos + size


def read_bytes(binary: bytes, pos: int, size: int) -> (bytes, int):
    return binary[pos : pos + size], pos + size
