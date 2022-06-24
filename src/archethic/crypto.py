import os
from .utils import is_hex, hex_to_uint8array, uint8array_to_int, concat_uint8array, int_to_uint8array, uint8array_to_hex
from typing import Union
import hashlib
import hmac
from Crypto.Cipher import AES
from nacl.signing import SigningKey
from nacl.public import Box, PrivateKey
from fastecdsa import curve, ecdsa, keys
from fastecdsa.curve import P256 as P256_curve
SOFTWARE_ID = 1


# Get the ID of a given hash algorithm
def get_hash_id(hash_name: str) -> int:
    """
    Get the ID of a given hash algorithm
    :param hash_name:
    :return: int corresponding to the hash algorithm
    """
    if hash_name == 'sha256':
        return 0
    elif hash_name == 'sha512':
        return 1
    elif hash_name == 'sha3-256':
        return 2
    elif hash_name == 'sha3-512':
        return 3
    elif hash_name == 'blake2b':
        return 4
    else:
        raise ValueError('Hash algorithm not supported')


# Get the hash algo name from the hash algorithm ID
def get_hash_name(hash_id: int):
    """
    Get the hash algo name from the hash algorithm ID
    :param hash_id:
    :return: algo name
    """
    if hash_id == 0:
        return 'sha256'
    elif hash_id == 1:
        return 'sha512'
    elif hash_id == 2:
        return 'sha3-256'
    elif hash_id == 3:
        return 'sha3-512'
    elif hash_id == 4:
        return 'blake2b'
    else:
        raise ValueError('Hash algorithm not supported')


# Get the ID of a given Elliptic curve
def get_curve_id(curve_name: str):
    if curve_name == 'ed25519':
        return 0
    elif curve_name == 'P256':
        return 1
    elif curve_name == 'secp256k1':
        return 2
    else:
        raise ValueError('Elliptic curve not supported')


# Get the Elliptic curve name from the curve ID
def get_curve_name(curve_id: int):
    if curve_id == 0:
        return 'ed25519'
    elif curve_id == 1:
        return 'P256'
    elif curve_id == 2:
        return 'secp256k1'
    else:
        raise ValueError('Elliptic curve not supported')


# Create a hash digest from the data with an hash algorithm identification prepending the digest
def hash_digest(content: Union[str, bytearray], algo: str):
    """
    Create a hash digest from the data with an hash algorithm identification prepending the digest
    :param content:
    :param algo:
    :return: hashed content
    """
    isinstance(content, str or bytearray), 'Content must be a string or a bytearray'

    if type(content) == str:
        if is_hex(content):
            content = hex_to_uint8array(content)
        else:
            content = content.encode()

    algo_id = get_hash_id(algo)
    digest = get_hash_digest(content, algo)

    return concat_uint8array(
        [
            bytearray([algo_id]),
            digest
        ]
    )


# get hash digest
def get_hash_digest(content: Union[str, bytearray], algo: str):
    if algo == 'sha256':
        return hashlib.sha256(content).digest()
    elif algo == 'sha512':
        return hashlib.sha512(content).digest()
    elif algo == 'sha3-256':
        return hashlib.sha3_256(content).digest()
    elif algo == 'sha3-512':
        return hashlib.sha3_512(content).digest()
    elif algo == 'blake2b':
        return hashlib.blake2b(content).digest()
    else:
        raise ValueError('Hash algorithm not supported')


def derive_keypair(seed: str, index: int, curve: str = "ed25519") -> (hex, hex):
    """
    Generate a keypair using a derivation function with a seed and an index. Each keys is prepending with a curve identification.
    :param seed: Seed used to derive the keys
    :param index: Index used to derive the keys
    :param curve: Curve used to derive the keys
    :return: (private key, public key)
    """
    isinstance(seed, str), 'Seed must be a string'
    isinstance(index, int), 'Index must be an integer'
    assert index >= 0, 'Index must be a positive number'
    isinstance(curve, str), 'Curve must be a string'

    #ok
    pv_Buf = derive_private_key(seed, index)

    return generate_deterministic_keypair(pv_Buf, curve, SOFTWARE_ID)


# Derive private key
def derive_private_key(seed, index: int) -> bytes:
    """
    Derive a private key from a seed and an index
    :param seed:
    :param index:
    :return: private_key
    """
    if is_hex(seed):
        seed = hex_to_uint8array(seed)

    # derive master keys
    hash = hashlib.sha512(seed.encode()).digest()
    master_key = hash[:32]
    master_entropy = hash[32:64]

    # derive final seed
    index_buf = int_to_uint8array(index)
    extended_seed = concat_uint8array([master_key, index_buf])

    hmacc = hmac.new(master_entropy,msg=extended_seed, digestmod="sha512")
    final_seed = hmacc.digest()
    return final_seed[:32]


def generate_deterministic_keypair(private_key, curve: str, origin_id: int) -> (bytearray, bytearray):
    """
    Generate a new keypair deterministically with a given private key, curve and origin id
    :param private_key:
    :param curve:
    :param origin_id:
    :return: (private key, public key)
    """
    isinstance(curve, str), 'Curve must be a string'
    isinstance(origin_id, int), 'Origin id must be an integer'

    curve_id = get_curve_id(curve)

    public_key, pv_key = get_key_pair(private_key, curve)

    return (
        concat_uint8array([bytearray([curve_id]), bytearray([origin_id]), private_key]).hex(),
        concat_uint8array([bytearray([curve_id]), bytearray([origin_id]), public_key]).hex()
    )


def get_key_pair(private_key: bytearray, curve: str) -> (bytearray, bytearray):
    """
    Get the public and private key from a private key
    :param private_key:
    :param curve:
    :return: (private key, public key)
    """
    isinstance(private_key, bytearray), 'Private key must be a bytearray'
    isinstance(curve, str), 'Curve must be a string'

    # Get private and public key
    if curve == 'ed25519':
        sk = SigningKey(private_key)
        pk = sk.verify_key

        return pk.__bytes__(), sk.__bytes__()

    elif curve == 'P256':
        raise NotImplementedError('P256 curve not implemented')

    elif curve == 'secp256k1':
        raise NotImplementedError('secp256k1 curve not implemented')


#Derive an address from a seed, an index, an elliptic curve and an hash algorithm.
def derive_address(seed: str, index: int, curve: str = "ed25519", algo: str = "sha256") -> hex:
    """
    Derive an address from a seed, an index, an elliptic curve and an hash algorithm.
    :param seed: Seed used to derive the address
    :param index: Index used to derive the address
    :param curve: Curve used to derive the address
    :param algo: Hash algorithm used to derive the address ("sha256", "sha512", "sha3-256", "sha3-512", "blake2b")
    :return: Address
    """
    isinstance(seed, str), 'Seed must be a string'
    isinstance(index, int), 'Index must be an integer'
    assert index >= 0, 'Index must be a positive number'

    pv_key, public_key = derive_keypair(seed, index, curve)

    curve_id = get_curve_id(curve)
    hashed_public_key = hash_digest(public_key, algo)

    return concat_uint8array(
        [
            bytearray([curve_id]),
            hashed_public_key,
        ]
    ).hex()


# TODO: implement ec_encrypt
def ec_encrypt(data: Union[str,bytearray], public_key: Union[str,bytearray], curve: str = "ed25519") -> hex:
    """
    Encrypt a data for a given public key using ECIES algorithm
    :param data: Data to encrypt
    :param public_key: Public key used to encrypt the data
    :param curve: Curve used to encrypt the data
    :return: Encrypted data
    """
    raise NotImplementedError('ec encryption not implemented')
    isinstance(data, str or bytearray), 'Data must be a string or a bytearray'
    isinstance(public_key, str or bytearray), 'Public key must be a string or a bytearray'
    isinstance(curve, str), 'Curve must be a string'

    if type(data) == str:
        if is_hex(data):
            data = hex_to_uint8array(data)
        else:
            data = data.encode()

    if type(public_key) == str:
        if is_hex(public_key):
            public_key = hex_to_uint8array(public_key)
        else:
            raise ValueError('Public key must be a hex string')

    curve_buf = public_key[0]
    pub_buf = public_key[1:]

    if curve_buf == 0:
        ephemeral_private_key = PrivateKey.generate()

        ephemeral_public_key = ephemeral_private_key.public_key

        crypto_box = Box(ephemeral_private_key, ephemeral_public_key)

        ciphertext = crypto_box.encrypt(data)
        aes_key, iv = derive_secret(crypto_box.shared_key())

        tag, encrypted = aes_auth_encrypt(aes_key, iv, data)


        return concat_uint8array(
            [
                bytearray(ephemeral_public_key.__bytes__()),
                tag,
                encrypted
            ]
        )


# TODO: implement ec_decrypt
def ec_decrypt(data: Union[str,bytearray], private_key: Union[str,bytearray], curve: str = "ed25519") -> str:
    raise NotImplementedError('ec decryption not implemented')


def derive_secret(shared_key: Union[str,bytearray, bytes]) -> (bytearray, bytearray):
    """
    Derive a secret from a shared key and an index
    :param shared_key:
    :param index:
    :return: (secret, iv)
    """
    isinstance(shared_key, str or bytearray or bytes), 'Shared key must be a string or a bytearray or bytes'

    if type(shared_key) == str:
        if is_hex(shared_key):
            shared_key = hex_to_uint8array(shared_key)
        else:
            raise ValueError('Shared key must be a hex string')

    pseudo_random_secret = hashlib.sha256(shared_key).digest()

    iv = hashlib.sha256(pseudo_random_secret)
    iv.update("0".encode())
    iv = iv.digest()[:32]

    aes_key = hashlib.sha256(iv)
    aes_key.update("1".encode())
    aes_key = aes_key.digest()[:32]

    return aes_key, iv

# TODO: implement aes_auth_encrypt
def aes_auth_encrypt(aes_key: bytearray, iv: bytearray, data: bytearray):
    raise NotImplementedError('aes_auth_encrypt not implemented')
    # cipher = AES.new(aes_key, AES.MODE_GCM, iv)
    # ciphertext, tag = cipher.encrypt_and_digest(data)
    # print(f"cipher :{ciphertext.hex()} tag :{tag.hex()}")
    # return bytearray(tag), ciphertext


# TODO: implement aes_decrypt
def aes_encrypt(data, key) -> bytearray:
    """
    Encrypt a data for a given public key using AES algorithm
    :param data:
    :param key:
    :return: encrypted data bytearray
    """
    raise NotImplementedError('aes_encrypt not implemented')


# TODO: implement aes_decrypt
def aes_decrypt(ciphertext, key) -> bytearray:
    """
    Decrypt data for a given public key using AES algorithm
    :param data:
    :param key:
    :return: encrypted data bytearray
    """
    raise NotImplementedError('aes_decrypt not implemented')