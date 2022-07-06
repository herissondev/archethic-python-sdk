from archethic.utils import is_hex, hex_to_uint8array, concat_uint8array, int_to_32
from nacl.signing import SigningKey
from nacl import bindings
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Crypto.Signature import eddsa
from fastecdsa import curve, ecdsa, keys
from fastecdsa.encoding.der import DEREncoder
from typing import Union
import hashlib
import hmac
import secp256k1

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
def hash_digest(content: Union[str, bytes], algo: str):
    """
    Create a hash digest from the data with an hash algorithm identification prepending the digest
    :param content:
    :param algo:
    :return: hashed content
    """
    isinstance(content, str or bytes), 'Content must be a string or a bytes'

    if type(content) == str:
        if is_hex(content):
            content = bytes.fromhex(content)
        else:
            content = content.encode()

    algo_id = get_hash_id(algo)
    digest = get_hash_digest(content, algo)

    return bytearray([algo_id]) + digest


# get hash digest
def get_hash_digest(content: Union[str, bytes], algo: str):
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
    index_buf = int_to_32(index)
    extended_seed = master_key + index_buf

    hmacc = hmac.new(master_entropy,msg=extended_seed, digestmod="sha512")
    final_seed = hmacc.digest()
    return final_seed[:32]


def generate_deterministic_keypair(private_key, curve: str, origin_id: int) -> (bytes, bytes):
    """
    Generate a new keypair deterministically with a given private key, curve and origin id
    :param private_key:
    :param curve:
    :param origin_id:
    :return: (private key, public key) in hex format
    """
    isinstance(curve, str), 'Curve must be a string'
    isinstance(origin_id, int), 'Origin id must be an integer'

    curve_id = get_curve_id(curve)

    public_key, pv_key = get_key_pair(private_key, curve)

    return (
        (bytearray([curve_id,origin_id]) + private_key).hex(),
        (bytearray([curve_id,origin_id]) + public_key).hex()
    )


def get_key_pair(private_key: bytes, curve: str) -> (bytes, bytes):
    """
    Get the public and private key from a private key
    :param private_key:
    :param curve:
    :return: (private key, public key) in bytes format
    """
    isinstance(private_key, bytes), 'Private key must be of type bytes'
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

    return (
            bytearray([curve_id]) + hashed_public_key
    ).hex()


def ec_encrypt(data: Union[str,bytes], public_key: Union[str,bytes]) -> hex:
    """
    Encrypt a data for a given public key using ECIES algorithm
    :param data: Data to encrypt
    :param public_key: Public key used to encrypt the data
    :return: Encrypted data in hex format
    """

    isinstance(data, str or bytes), 'Data must be a string or a bytes'
    isinstance(public_key, str or bytes), 'Public key must be string or bytes'

    if type(data) == str:
        if is_hex(data):
            data = bytes.fromhex(data)
        else:
            data = data.encode()

    if type(public_key) == str:
        if is_hex(public_key):
            public_key = bytes.fromhex(public_key)
        else:
            raise ValueError('Public key must be a hex string')

    curve_buf = public_key[0]
    pub_buf = public_key[2:]

    if curve_buf == 0:

        ephemeral_public_key, ephemeral_private_key = bindings.crypto_box_keypair()
        curve25519_pub = bindings.crypto_sign_ed25519_pk_to_curve25519(pub_buf)

        shared_key = bindings.crypto_scalarmult_ed25519(n=ephemeral_private_key, p=curve25519_pub)

        aes_key, iv = derive_secret(shared_key)

        encrypted, tag = aes_auth_encrypt(aes_key, iv, data)

        return (ephemeral_public_key + tag + encrypted).hex()



    # TODO : implement prime256v1 encryption
    elif curve_buf == 1:
        raise NotImplementedError("prime256v1 encryption not implemented yet")

    # TODO : implement secp256k1 encryption
    elif curve_buf == 2:
        raise NotImplementedError("secp256k1 encryption not implemented yet")

    else:
        raise ValueError("Curve not supported")


def ec_decrypt(ciphertext: Union[str,hex], private_key: Union[str,bytes], curve: str = "ed25519") -> any:
    '''
    Decrypt a ciphertext for a given private key using ECIES algorithm
    :param ciphertext:
    :param private_key:
    :param curve:
    :return:
    '''
    isinstance(ciphertext, str or bytes), 'Ciphertext must be a string or a bytes'
    isinstance(private_key, str or bytes), 'Private key must be a string or a bytes'
    isinstance(curve, str), 'Curve must be a string'



    if type(ciphertext) == str:
        if is_hex(ciphertext):
            ciphertext = bytes.fromhex(ciphertext)
        else:
            ciphertext = ciphertext.encode()

    if type(private_key) == str:
        if is_hex(private_key):
            private_key = bytes.fromhex(private_key)
        else:
            raise ValueError('Private key must be a hex string')

    curve_buf = private_key[0]
    priv_buf = private_key[2:]

    if curve_buf == 0:

        ephemeral_public_key = ciphertext[:32]
        tag = ciphertext[32:48]
        encrypted = ciphertext[48:]

        curve_buf_pv = bindings.crypto_sign_ed25519_sk_to_curve25519(priv_buf)

        shared_key = bindings.crypto_scalarmult_ed25519(curve_buf_pv, bytes(ephemeral_public_key))

        aes_key, iv = derive_secret(shared_key)

        return aes_auth_decrypt(bytes(encrypted), bytes(aes_key), bytes(iv), bytes(tag))








    raise NotImplementedError('ec decryption not implemented')


def derive_secret(shared_key: Union[str, bytes]) -> (bytes, bytes):
    """
    Derive a secret from a shared key and an index
    :param shared_key:
    :param index:
    :return: (secret, iv)
    """
    isinstance(shared_key, str or bytes), 'Shared key must be a string or bytes'

    if type(shared_key) == str:
        if is_hex(shared_key):
            shared_key = hex_to_uint8array(shared_key)
        else:
            raise ValueError('Shared key must be a hex string')

    pseudo_random_secret = hashlib.sha256(shared_key).digest()

    iv = hmac.new(pseudo_random_secret, "0".encode(), "sha256")
    iv = iv.digest()[:32]

    aes_key =  hmac.new(iv, "1".encode(), "sha256")
    aes_key = aes_key.digest()[:32]

    return aes_key, iv


def aes_auth_encrypt(aes_key: bytes, iv: bytes, data: bytes) -> (bytes, bytes):
    '''
    Encrypt a data using AES-256-GCM
    :param aes_key: aes key in bytes
    :param iv: iv in bytes
    :param data: data in bytes
    :return: (encrypted data, tag)
    '''
    cipher = AES.new(aes_key, AES.MODE_GCM, iv)
    return cipher.encrypt_and_digest(data)


def aes_auth_decrypt(encrypted: bytes, aes_key: bytes, iv: bytes, tag: bytes) -> (bytes, bytes):
    cipher = AES.new(aes_key, AES.MODE_GCM, iv)
    data = cipher.decrypt(encrypted)
    return data


def aes_encrypt(data: Union[str,bytes], public_key: Union[str,bytes]) -> bytes:
    """
    Encrypt a data for a given public key using AES algorithm
    :param data:
    :param public_key:
    :return: encrypted data in bytes
    """

    isinstance(data, str or bytes), 'Data must be a string or a bytes'
    isinstance(public_key, str or bytes), 'Public key must be a string or a bytes'

    if type(data) == str:
        if is_hex(data):
            data = bytes.fromhex(data)
        else:
            data = data.encode()

    if type(public_key) == str:
        if is_hex(public_key):
            public_key = bytes.fromhex(public_key)
        else:
            raise ValueError('Public key must be a hex string')

    iv = get_random_bytes(12)
    encrypted, tag = aes_auth_encrypt(public_key, iv, data)

    return iv + tag + encrypted


def aes_decrypt(ciphertext: Union[str, bytes], key: Union[str, bytes]) -> bytes:
    """
    Decrypt data for a given public key using AES algorithm
    :param data: data in bytes or hex string
    :param key: private key in bytes or hex string
    :return: decrypted data in bytes
    """
    isinstance(ciphertext, str or bytes), 'Ciphertext must be of type string or bytes'
    isinstance(key, str or bytes), 'Key must be of type string or bytes'

    if type(ciphertext) == str:
        if is_hex(ciphertext):
            ciphertext = bytes.fromhex(ciphertext)
        else:
            raise ValueError('Ciphertext must be a hex string')

    if type(key) == str:
        if is_hex(key):
            key = bytes.fromhex(key)
        else:
            raise ValueError('Key must be a hex string')

    iv = ciphertext[:12]
    tag = ciphertext[12:28]
    encrypted = ciphertext[28:]

    return aes_auth_decrypt(encrypted, key, iv, tag)


def sign(data: Union[str, bytes], private_key: Union[str, bytes]) -> bytes:
    """
    Sign a data using EdDSA algorithm
    :param data:
    :param private_key:
    :return:
    """
    isinstance(data, str or bytes), 'Data must be of type string or bytes'
    isinstance(private_key, str or bytes), 'Private key must be of type string or bytes'

    if type(data) == str:
        if is_hex(data):
            data = bytes.fromhex(data)
        else:
            data = data.encode()

    if type(private_key) == str:
        if is_hex(private_key):
            private_key = bytes.fromhex(private_key)
        else:
            raise ValueError('Private key must be a hex string')

    curve_buf = private_key[0]
    priv_buf = private_key[2:]

    if curve_buf == 0:
        key = eddsa.import_private_key(priv_buf)
        signer = eddsa.new(key,mode='rfc8032')
        return signer.sign(data)

    elif curve_buf == 1:
        r,s = ecdsa.sign(data, int(priv_buf.hex(), 16), curve=curve.P256)
        print(f"DEREncoder: {DEREncoder.encode_signature(r, s).hex()}")
        return DEREncoder.encode_signature(r,s)

    elif curve_buf == 2:
        hashData = hashlib.sha256(data).digest()
        key = secp256k1.PrivateKey(priv_buf, raw=True)
        sig_check = key.ecdsa_sign(hashData, raw=True)
        return key.ecdsa_serialize_compact(sig_check)


    else:
        raise ValueError("Curve not supported")