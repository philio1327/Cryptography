####################################################################################################
#  File Name: assignment4_q1_8191716.py                                                            #
#  Description: Implement HMAC-SHA-512                                                             #
#  Usage: Run from Pycharm or any other IDE, or                                                    #
#         Terminal: python assignment4_q1_8191716.py                                               #
#  Author: Philip Anderegg                                                                         #
#  Created On: 22-11-2024                                                                          #
#  Last Modified On: 26-11-2024                                                                    #
#  Student Number: 8191716                                                                         #
#  Course Name: Cryptography                                                                       #
#  Course Code: CSI 4108                                                                           #
#  Professor: Dr. Carlisle Adams                                                                   #
#  Due Date: Friday, November 29th, 2024                                                           #
####################################################################################################

import hashlib
import hmac
from typing import Union


def sha_512(plaintext: Union[str, int, float]) -> str:
    """
    Computes the SHA-512 hash of the input plaintext.

    This function accepts various input types (string, integer, or float),
    converts them into a string, and computes the SHA-512 hash.

    Parameters:
        plaintext (Union[str, int, float]): Input message to be hashed

    Returns:
        str: The hexadecimal SHA-512 hash of input plaintext.

    Examples:
        > sha_512(12345)
        '3627909a29c31381a071ec27f7c9ca97726182aed29a7ddd2e54353322cfb30abb9e3a6df2ac2c20fe23436311d678564d0c8d305930575f60e2d3d048184d79'
    """
    return hashlib.sha512(str(plaintext).encode("utf-8")).hexdigest()

def sha_512_bytes(plaintext: bytes) -> str:
    """
    Computes the SHA-512 hash of the input plaintext bytes type.

    Parameters:
        plaintext (bytes): Input bytes to be hashed.

    Returns:
        str: The hexadecimal SHA-512 hash of input plaintext.
    """
    return hashlib.sha512(plaintext).hexdigest()

def pad_key(key: bytes, block_size: int) -> bytes:
    """
    Pads or hashes a given key to conform to a specified block size.

    If the key is longer than the block size, it is hashed using SHA-512.
    If the key is shorter, it is right-padded with null bytes (b'\\x00').

    Args:
        key (bytes): The input key to be padded or hashed.
        block_size (int): The desired block size in bytes.

    Returns:
        bytes: The resulting key, adjusted to the specified block size.

    Examples:
        > pad_key("my_key".encode("utf-8", 12)
        b'my_key\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    """
    if len(key) > block_size:
        key = hashlib.sha512(key).digest()
    if len(key) < block_size:
        key = key.ljust(block_size, b'\x00')
    return key

def hmac_sha_512(key: str, message: str) -> str:
    """
    Computes the HMAC of the input message string using the provided key and SHA-512.

    HMAC (Hash-based Message Authentication Code) is a mechanism to verify the integrity
    and authenticity of a message. This implementation uses SHA-512 as the underlying hash function.

    Parameters:
        key (str): The secret key used for generating the HMAC. It can be of any length.
        message (str): The message to be authenticated.

    Returns:
        str: The hexadecimal HMAC value of the input message.

    Examples:
        > hmac_sha_512("my_secret_key", "Hello, World!")
        '2f451791d68295120000fb128dc8ba190831b98214020743dbfa495d75dc6db2ac74b09192780f424d0682979eceb930a339dcea2835fec54b0635943cb06c8b'

    Notes:
        - The block size for SHA-512 is 128 bytes (1024 bits).
        - If the key is longer than the block size, it is hashed to reduce its length.
        - If the key is shorter than the block size, it is padded with null bytes.
    """
    # First pad the key - Note that sha-512 has a block-size of 1024 bits, or 128 bytes
    key_bytes = key.encode("utf-8")
    padded_key = pad_key(key_bytes, 128)

    # Next we construct our inner pad and then XOR with our padded key *Note ipad must be in bytes
    ipad = bytes([0x36] * 128)
    k_xor_ipad = bytes([b ^ p for b, p in zip(padded_key, ipad)])

    # Next we concatenate this with our message
    message_bytes = message.encode("utf-8")
    concatenated = k_xor_ipad + message_bytes

    inner_hash = hashlib.sha512(concatenated).digest()

    # Next we do the outer hash
    opad = bytes([0x5c] * 128)
    outer_hash = bytes([b ^ p for b, p in zip(padded_key, opad)])

    result = outer_hash + inner_hash
    return sha_512_bytes(result)

def hmac_sha512_library(key: str, message: str) -> str:
    """
    Computes the HMAC of the input message string using the provided key and SHA-512,
    leveraging Python's `hmac` library.

    Parameters:
        key (str): The secret key used for generating the HMAC. It can be of any length.
        message (str): The message to be authenticated.

    Returns:
        str: The hexadecimal HMAC value of the input message.

    Examples:
        > hmac_sha512_library("my_secret_key", "Hello, World!")
        '2f451791d68295120000fb128dc8ba190831b98214020743dbfa495d75dc6db2ac74b09192780f424d0682979eceb930a339dcea2835fec54b0635943cb06c8b'

    Notes:
        - This implementation uses Python's built-in `hmac` library, which is optimized and
          adheres to the HMAC standard.
        - The block size of the hash function (SHA-512 in this case) is automatically handled by the library.
        """
    key_bytes = key.encode("utf-8")
    message_bytes = message.encode("utf-8")

    hmac_object = hmac.new(key_bytes, message_bytes, hashlib.sha512)
    return hmac_object.hexdigest()

if __name__ == "__main__":
    print(f"Input: Hello, SHA-512 Hash: {sha_512("Hello")}")
    print(f"Input: 123456789 (as integer), SHA-512 Hash: {sha_512(123456789)}")
    print("HMAC-SHA-512: ")
    print("Key: my_key")
    print("Message: my_message")
    print(f"HMAC Hash Using Own Code: {hmac_sha_512("my_key", "my_message")}")
    test_string = "I am using this input string to test my own implementation of HMAC-SHA-512."
    key = "my_key"
    print(f"Key: {key}")
    print(f"Message: {test_string}")
    hmac_self = hmac_sha_512(key, test_string)
    hmac_library = hmac_sha512_library(key, test_string)
    print(f"HMAC Hash Using Own Code: {hmac_self}")
    print(f"HMAC Hash Using Library: {hmac_library}")
    print(f"Outputs are the same? {hmac_self == hmac_library}")
