from time import perf_counter
from cryptography.hazmat.primitives.asymmetric import rsa
from assignment_3_q1_8191716 import mod_inverse


def generate_1024_bit_prime(bits: int) -> (int, int):
    """
    Generates two large primes, p and q, of approximately the specified bit size using RSA key generation.

    Parameters:
        bits (int): The desired bit size for each of the generated primes.

    Returns:
        tuple: A tuple (p, q) containing two prime numbers, each approximately `bits` bits in size.

    Note:
        The `key_size` for the RSA key generation is set to `bits * 2` to ensure that the two primes,
        p and q, meet the required bit size.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits * 2
    )
    p, q = private_key.private_numbers().p, private_key.private_numbers().q
    return p, q

def rsa_encrypt(m: int, n: int, e: int) -> int:
    """
    Encrypts a message using RSA encryption, using modular exponentiation: c = (m^e) mod n.

    Parameters:
        m (int): The plaintext message represented as an integer. It should satisfy 0 <= m < n.
        n (int): The modulus, part of the RSA public key.
        e (int): The public exponent, part of the RSA public key.

    Returns:
        int: The ciphertext resulting from encrypting the message m.

    """
    return pow(m, e, n)

def rsa_decrypt(c: int, p: int, q: int, e: int) -> int:
    """
    Decrypts a ciphertext using RSA decryption.

    Parameters:
        c (int): The ciphertext to decrypt. It should satisfy 0 <= c < p * q.
        p (int): One of the prime factors of the RSA modulus.
        q (int): The other prime factor of the RSA modulus.
        e (int): The public exponent used for encryption.

    Returns:
        int: The decrypted plaintext message.

    Raises:
        ValueError: If modular inverse of e with respect to phi(n) cannot be calculated.

    Formula:
        1. Calculate φ(n) = (p - 1)(q - 1), where n = p * q.
        2. Compute the private exponent d = e⁻¹ mod φ(n).
        3. Decrypt using modular exponentiation: m = c^d mod n.
    """
    phi_n = (p - 1) * (q - 1)
    d = mod_inverse(e, phi_n)
    return pow(c, d, (p*q))

def rsa_decrypt_crt(c: int, p: int, q: int, e: int) -> int:
    """
    Decrypts a ciphertext using RSA decryption with the Chinese Remainder Theorem (CRT).

    Parameters:
        c (int): The ciphertext to decrypt. It should satisfy 0 <= c < p * q.
        p (int): One of the prime factors of the RSA modulus.
        q (int): The other prime factor of the RSA modulus.
        e (int): The public exponent used for encryption.

    Returns:
        int: The decrypted plaintext message.

    Raises:
        ValueError: If the modular inverse of `e` or `q` with respect to `p` cannot be calculated.

    """
    phi_n = (p - 1) * (q - 1)
    d = mod_inverse(e, phi_n)
    # Compute d_p and d_q from d
    d_p = d % (p-1)
    d_q = d % (q-1)

    # C_p and C_q computation
    C_p = pow(c, d_p, p)
    C_q = pow(c, d_q, q)

    q_inv = mod_inverse(q, p)

    # Calculate final message using CRT
    M = (C_p - C_q) * q_inv % p
    M = M * q + C_q
    return M % (p*q)


if __name__ == "__main__":
    size = 1024
    p, q = generate_1024_bit_prime(size)
    e = 65537
    print(f"Generated {size}-bit primes:")
    print(f"P: {p}")
    print(f"Q: {q}\n")
    n = p * q
    print(f"Modulus is: {n}")
    m = 476931823457909
    print(f"Message to encrypt: {m}")
    c = rsa_encrypt(m, n, e)
    print(f"Ciphertext is: {c}")
    time_start = perf_counter()
    print(f"Decrypt cipher knowing p, q and e: {rsa_decrypt(c, p, q, e)}")
    time_end = perf_counter()
    print(f"Decrypt Time: {time_end - time_start} ms")
    crt_start = perf_counter()
    print(f"Decrypt cipher using CRT: {rsa_decrypt_crt(c, p, q, e)}")
    crt_end = perf_counter()
    print(f"Decrypt Time: {crt_end - crt_start} ms")



