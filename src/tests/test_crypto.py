import archethic.crypto as Crypto


def test_hashes():
    assert (
        Crypto.hash_digest("myfakedata", "sha256").hex()
        == "004e89e81096eb09c74a29bdf66e41fc118b6d17ac547223ca6629a71724e69f23"
    )
    assert (
        Crypto.hash_digest("myfakedata", "sha512").hex()
        == "01c09b378f954c39f8e3c2cc4ed9108937c6e6dbfa9f754a344bd395d2ba55aba9f071987a2c014f9c54d47931b243088aa2dd6c6d90ec92a67f8a9dfdd83eba58"
    )
    assert (
        Crypto.hash_digest("myfakedata", "sha3-256").hex()
        == "029ddb36eabafb047ad869b9e4d35e2c5e6893b6bd2d1cdbdaec13425779f0f9da"
    )
    assert (
        Crypto.hash_digest("myfakedata", "sha3-512").hex()
        == "03f64fe5d472619d235212f843c1ed8ae43598c3a5973eead66d70f88f147a0aaabcbcdc6aed160b0ae5cdf5d48871602827b242c479f999647c377698cb8b7d4f"
    )
    assert (
        Crypto.hash_digest("myfakedata", "blake2b").hex()
        == "04f4101890104371a4d673ed717e824c80634edf3cb39e3eeff555049c0a025e5f13a6aa938c7501a98471cad9c13870c13e8691e97229e4a4b4e1930221c02ab8"
    )


def test_derive_keypair():
    sk, pk = Crypto.derive_keypair("seed", 0, curve="ed25519")
    assert pk == "000161d6cd8da68207bd01198909c139c130a3df3a8bd20f4bacb123c46354ccd52c"


def test_change_index():
    sk_1, pk_1 = Crypto.derive_keypair("seed", 0, curve="ed25519")
    sk_2, pk_2 = Crypto.derive_keypair("seed", 1, curve="ed25519")
    assert sk_1 != sk_2
    assert pk_1 != pk_2


def test_ec_encrypt_ed25519():

    sk, pk = Crypto.derive_keypair("seed", 0, curve="ed25519")
    cipher = Crypto.ec_encrypt("hello", pk)
    print(len(bytes.fromhex(sk)[2:]))

    assert Crypto.ec_decrypt(cipher, sk) == "hello".encode()


def test_aes_encrypt():
    key = Crypto.random_secret_key()
    cipher = Crypto.aes_encrypt("hello", key)
    assert Crypto.aes_decrypt(cipher, key) == "hello".encode()


def test_sign_ed25519():
    sk, pk = Crypto.derive_keypair("seed", 0, curve="ed25519")
    sig = Crypto.sign("hello", sk)
    assert Crypto.verify(sig, "hello", pk) is True
