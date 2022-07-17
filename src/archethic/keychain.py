from archethic.transaction_builder import TransactionBuilder
from archethic.utils import int_to_32, int_to_64
from archethic.crypto import generate_deterministic_keypair, derive_address, hash_digest, get_curve_id, get_hash_id, get_curve_name, get_hash_name, sign
from typing import Union, Dict
import json
import hmac
import hashlib


KEYCHAIN_ORIGIN_ID = 0


class Keychain:

    def __init__(self, seed: Union[str, bytes], version: int = 1) -> None:
        """

        :param seed:
        """

        if not isinstance(seed, bytes):
            seed = seed.encode()
        elif not isinstance(seed, str):
            raise ValueError("Seed must be bytes or string")

        self.seed: bytes = seed
        self.version: int = version
        self.services: dict = {}

        self.add_service("uco", "m/650'/0/0")

    def add_service(self, service_name: str, derivation_path, curve: str = "ed25519", hash_algo: str = "sha256") -> None:
        self.services[service_name] = {
            "derivationPath": derivation_path,
            "curve": curve,
            "hashAlgo": hash_algo
        }

    def encode(self) -> bytes:

        service_buffer = []

        for service in self.services:
            _service = self.services[service]
            service_buffer.append(
                (
                    bytearray([len(_service)]) +
                    json.dumps(_service).encode() +
                    bytearray( [ len(_service['derivationPath']) ] ) +
                    _service['derivationPath'].encode() +
                    bytearray([get_curve_id(_service['curve'])]) +
                    bytearray([get_hash_id(_service['hashAlgo'])])
                )
            )

        return (
            int_to_32(self.version) +
            bytearray([len(self.seed)]) +
            self.seed +
            bytearray([len(self.services.keys())])
            + b''.join(service_buffer)
        )

    def derive_keypair(self, service: str, index: int = 0):

        if not service in self.services:
            raise ValueError("Service doesn't exist in the keychain")

        _service = self.services[service]

        return derive_archethic_keypair(self.seed, _service['derivationPath'], index, _service['curve'])

    def derive_address(self, service: str, index: int = 0):

        if service not in self.services:
            raise ValueError("Service doesn't exist in the keychain")

        _service = self.services[service]
        derivation_path = _service['derivationPath']
        curve = _service['curve']
        hash_algo = _service['hashAlgo']

        sk, pk = derive_archethic_keypair(self.seed, derivation_path, index, curve)
        curve_id = get_curve_id(curve)

        hashed_public_key = hash_digest(pk, hash_algo)

        return bytearray([curve_id]) + hashed_public_key

    def build_tx(self, tx: TransactionBuilder, service: str, index: int) -> TransactionBuilder:
        sk, pk = self.derive_keypair(service, index)
        address = self.derive_address(service, index + 1)

        tx.set_address(address)

        payload_for_previous_signature = tx.previous_signature_payload()
        previous_signature = sign(payload_for_previous_signature, sk)

        tx.set_previous_signature_and_previous_public_key(previous_signature, pk)

        return tx




def derive_archethic_keypair(seed: bytes, derivation_path, index, curve = "ed25519"):
    hashed_path = hashlib.sha256(replace_derivation_path_index(derivation_path, index)).digest()
    extended_seed = hmac.new(seed, hashed_path, "sha512").digest()[:32]
    return generate_deterministic_keypair(extended_seed, curve, KEYCHAIN_ORIGIN_ID)

def replace_derivation_path_index(path: str, index):
    path = path.split('/')
    path = path[:-1]
    path.append(f"{index}'")
    path = '/'.join(path)
    return path



