from typing import Union
import struct

#Origin private key
ORIGIN_PRIVATE_KEY = '01019280BDB84B8F8AEDBA205FE3552689964A5626EE2C60AA10E3BF22A91A036009'


# Check if a string is hexadecimal
def is_hex(string: str) -> bool:
    try:
        int(string, 16)
        return True
    except ValueError:
        return False


# Encode an hexadecimal string into Uint8Array
def hex_to_uint8array(hex_string: str) -> bytearray:
    if not is_hex(hex_string):
        raise ValueError("The string is not hexadecimal")
    return bytearray.fromhex(hex_string)


# Decode an Uint8Array into an hexadecimal string
def uint8array_to_hex(uint8array: bytearray):
    return uint8array.hex()


# Concat a list of Uint8Array
def concat_uint8array(uint8array_list: list) -> bytearray:
    return bytearray(b''.join(uint8array_list))

# Encode a integer into a Uint8Array (4 bytes)
def int_to_32(int_value: int) -> bytes:
    return int_value.to_bytes(4, byteorder='big')


# Encode a big integer into a Uint8Array (8 bytes)
def int_to_64(big_int_value: int) -> bytes:
    return big_int_value.to_bytes(8, byteorder='big')


# Decode byte array (4 bytes) into an integer
def uint8array_to_int(uint8array: bytearray) -> int:
    return struct.unpack("<I", uint8array)[0]


# Convert any number into a big int for 10^8 decimals
def to_big_int(number: Union[int,float]) -> int:
    return round(number * 100000000)
