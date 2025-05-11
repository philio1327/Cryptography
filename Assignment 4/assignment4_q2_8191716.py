####################################################################################################
#  File Name: assignment4_q2_8191716.py                                                            #
#  Description: Implement DSA                                                                      #
#  Usage: Run from Pycharm or any other IDE, or                                                    #
#         Terminal: python assignment4_q2_8191716.py                                               #
#  Author: Philip Anderegg                                                                         #
#  Created On: 23-11-2024                                                                          #
#  Last Modified On: 26-11-2024                                                                    #
#  Student Number: 8191716                                                                         #
#  Course Name: Cryptography                                                                       #
#  Course Code: CSI 4108                                                                           #
#  Professor: Dr. Carlisle Adams                                                                   #
#  Due Date: Friday, November 29th, 2024                                                           #
####################################################################################################
import hashlib
import timeit
import time
from cryptography.hazmat.primitives.asymmetric import rsa
import random

def generate_prime(size: int) -> int:
    """
    Generates a random prime number of the specified size using RSA private key generation.

    Parameters:
        size (int): The size of the prime number in bits. The function generates a prime
                    with approximately `size` bits by creating a key of `size * 2` bits
                    and extracting one of the prime factors.

    Returns:
        int: A prime number with approximately the specified bit size.

    Examples:
        > prime = generate_prime(1024)
        > print(prime.bit_length())  # Approximately 1024 bits

    Notes:
        - This method leverages the RSA private key generation from the `cryptography` library,
          which internally generates two prime numbers to construct the RSA modulus.
        - The `p` component of the private key is returned as the prime.
        - Ensure that the `cryptography` library is installed to use this function.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=size * 2)
    return key.private_numbers().p

def hash_message(message: int) -> str:
    message_bytes = message.to_bytes((message.bit_length() + 7) // 8, byteorder='big')
    return hashlib.sha1(message_bytes).hexdigest()

def miller_rabin(n: int, rounds: int = 40) -> bool:
    """
    Perform the Miller-Rabin primality test on a given integer 'n'.

    Parameters:
    - n (int): The integer to test for primality. Should be greater than 2.
    - rounds (int): Number of random bases to test for confidence.

    Returns:
    - bool: True if 'n' is likely prime, False if 'n' is definitely composite.

    Examples:
        > miller_rabin(561, rounds=40)  # Composite
        False
        > miller_rabin(1019, rounds=40)  # Prime
        True
    """
    # Handle edge cases
    if n <= 1:
        return False
    if n <= 3 or n == 5 or n == 7 or n == 11 or n == 13:
        return True
    if n % 2 == 0 or n % 3 == 0 or n % 5 == 0 or n % 7 == 0 or n % 11 == 0 or n % 13 == 0:
        return False

    # Decompose (n - 1) into 2^k * q
    q = n - 1
    k = 0
    while q % 2 == 0:
        q //= 2
        k += 1

    # Perform the test 'rounds' times
    for _ in range(rounds):
        a = random.randint(2, n - 2)
        x = pow(a, q, n)  # Compute a^q % n
        if x == 1 or x == n - 1:
            continue # satisfies Miller-Rabin for this base "a"
        for _ in range(k - 1):
            x = pow(x, 2, n) # Compute a^(2^j) mod n for some j, and see if we get -1 mod n. Done by repeated squaring
            if x == n - 1:
                break
        else:
            return False  # Composite if no 'a^(2^j * q) ≡ -1 (mod n)' is found

    return True  # Likely prime

def generate_prime_small(size: int) -> int:
    """
    Generate a small prime number of approximately the specified bit size.

    Parameters:
        size (int): The desired bit size of the prime number. Must be a positive integer.

    Returns:
        int: A randomly generated prime number with the specified bit size.

    Examples:
        > generate_prime_small(8)
        193  # (Example result; actual output is random)
        > generate_prime_small(16)
        65521  # (Example result; actual output is random)

    Notes:
        - The function ensures the prime number is within the range of the specified bit size.
        - The Miller-Rabin test is used for primality checking to ensure high confidence.

    Raises:
        ValueError: If the size is less than 2, as no primes exist with fewer than 2 bits.
    """
    cand_prime = random.randint(pow(2, size-1), pow(2, size) - 1)
    while not miller_rabin(cand_prime):
        cand_prime = random.randint(pow(2, size-1), pow(2, size) - 1)
    return cand_prime

def generate_dsa_primes() -> (int, int):
    """
    Generate the primes `p` and `q` for the Digital Signature Algorithm (DSA).

    Returns:
        tuple[int, int]: A tuple containing:
            - p (int): A 1024-bit prime.
            - q (int): A 160-bit prime such that `q` divides `(p - 1)`.

    Examples:
        > p, q = generate_dsa_primes()
        > print(len(bin(p)) - 2)  # Bit length of p
        1024
        > print(len(bin(q)) - 2)  # Bit length of q
        160
        > print((p - 1) % q == 0)  # Verify q divides (p - 1)
        True

    Notes:
        - This method ensures the conditions required for DSA: a 1024-bit prime `p` and a 160-bit prime `q` such that `q` divides `(p - 1)`.
        - The Miller-Rabin primality test is used to ensure `p` is prime.
    """
    # Generate a 160-bit prime q
    q = generate_prime_small(160)

    # Find a 1024-bit prime p such that q | (p - 1)
    while True:
        k = random.randint(pow(2, 863), pow(2, 864) - 1)  # Generate a random k
        p = k * q + 1
        if p.bit_length() == 1024 and miller_rabin(p):  # Check p is 1024 bits and prime
            return p, q

def generate_h(p: int, q: int) -> int:
    """
   Generate a generator `h` for the subgroup of order `q` in the multiplicative group of integers modulo `p`.

   Parameters:
       p (int): A prime number such that `p - 1` is divisible by `q`.
       q (int): A prime divisor of `p - 1`.

   Returns:
       int: A valid generator `h` for the subgroup of order `q`.

   Examples:
       > p, q = 103687, 1571  # Example primes
       > h = generate_h(p, q)
       > pow(h, (p - 1) // q, p) != 1  # `h` should be a valid generator
       True

    """
    cand_h = random.randint(2, p-2)
    exponent = (p - 1) // q
    while pow(cand_h, exponent, p) == 1:
        cand_h = random.randint(2, p - 2)
    return cand_h

def test_large_prime() -> None:
    """
    Tests the generate_prime() function and times how long it takes to generate 1 000, 1024-bit primes.

    Returns:
         None
    """
    start_large = time.time()
    p = generate_prime(1024)
    end_large = time.time()
    print(f"1024-bit Prime: {p}")
    print(f"Time to generate 1024-bit prime: {end_large - start_large} Seconds")
    print(f"Timing 1024-bit Prime Generator...")
    elapsed_large = timeit.timeit(lambda: generate_prime(1024), number=1_000)
    print(f"Elapsed Time (1 000 runs): {elapsed_large} Seconds")
    print(f"Average Time per 1024-bit prime generated: {elapsed_large / 1_000} Seconds")

def test_small_prime() -> None:
    """
    Tests the generate_prime_small() function and times how long it takes to generate 10 000 small primes.

    Returns:
         None
    """
    start_time = time.time()
    q = generate_prime_small(160)
    print(f"\n160-bit Prime: {q}")
    end_time = time.time()
    print(f"Time to generate 160-bit prime: {end_time - start_time} Seconds")
    print("Timing 160-bit Prime Generator...")
    elasped_time = timeit.timeit(lambda: generate_prime_small(160), number=10_000)
    print(f"Elapsed Time (10 000 runs): {elasped_time} Seconds")
    print(f"Average Time per 160-bit prime generated: {elasped_time / 10_000} Seconds")

def dsa_global_keys() -> (int, int, int):
    """
    Generates DSA (Digital Signature Algorithm) global parameters (p, q, g) and prints details.

    This function:
    - Generates a prime number p and a divisor q such that q divides p-1.
    - Verifies that q divides p-1.
    - Generates a value h (a random number), and computes g as h^(p-1)//q % p.

    It also measures and prints the time taken to generate the parameters and checks the validity of q.

    Returns:
        tuple: A tuple containing the DSA global parameters (p, q, g).
            - p (int): A 1024-bit prime number.
            - q (int): A 160-bit prime divisor of p-1.
            - g (int): The generator of the group.

    Example:
        > p, q, g = dsa_global_keys()
        Here are the DSA Primes:
        P: 929834867071415760383718313908502495393345953068...
        Q: 916310265805773963626034282660940648690829531441
        Time to generate DSA Primes: 0.6632964611053467 Seconds
        Does Q divide P-1? True
        Generated h: 34337000127553737056401747134830464092299397396655131409268...
        Generated g: 45374098097609785888362096192089460336542753397806702906655...
    """
    start_dsa = time.time()
    p, q = generate_dsa_primes()
    end_dsa = time.time()
    print(f"\nHere are the DSA Primes:\nP: {p}\nQ: {q}")
    print(f"Time to generate DSA Primes: {end_dsa - start_dsa} Seconds")
    print(f"Does Q divide P-1? {(p - 1) % q == 0}")
    h = generate_h(p, q)
    print(f"Generated h: {h}")
    exponent = (p-1) // q
    g = pow(h, exponent, p)
    print(f"Generated g: {g}")
    return p, q, g

def dsa_keys_and_num(g: int, p: int, q: int) -> (int, int, int):
    """
    Generates the DSA keys and per-message secret number.

    This function generates the following:
    - A private key (x) for the user, which is a random integer in the range [1, q-1].
    - A public key (y) for the user, which is calculated as y = g^x % p.
    - A per-message secret number (k), which is a random integer in the range [1, q-1].

    The function prints the values of x, y, and k.

    Parameters:
        g (int): The generator of the group.
        p (int): A large prime number.
        q (int): A prime divisor of p-1.

    Returns:
        tuple: A tuple containing the DSA keys and the per-message secret number.
            - x (int): The user's private key.
            - y (int): The user's public key.
            - k (int): The user's per-message secret number.

    Example:
        > x, y, k = dsa_keys_and_num(g=12345, p=103687, q=1571)
        User's Private Key (x): 357584895070831425696066133990089799842548817891
        User's Public Key (y): 841211401073576544103769279833703626094279109699456774826536222...
        User's Per-Message Secret Number (k): 419486378045012511632749229071745616292573736528
    """
    x = random.randint(1, q-1)
    print(f"User's Private Key (x): {x}")
    y = pow(g, x, p)
    print(f"User's Public Key (y): {y}")
    k = random.randint(1, q-1)
    print(f"User's Per-Message Secret Number (k): {k}")
    return (x, y, k)

def dsa_signature(message: int, g: int, k: int, p: int, q: int, x: int) -> (int, int):
    """
    Generates a DSA signature for a given message using the user's private key and other DSA parameters.

    The signature is generated using the following formula:
    - r = (g^k % p) % q
    - s = (k_inv * (hashed_message + x * r)) % q
    where:
    - k_inv is the modular inverse of k mod q
    - hashed_message is the hash of the message
    - x is the user's private key
    - r is the first part of the signature
    - s is the second part of the signature

    Parameters:
        message (int): The message to be signed.
        g (int): The generator of the group.
        k (int): The per-message secret number.
        p (int): A large prime number.
        q (int): A prime divisor of p-1.
        x (int): The user's private key.

    Returns:
        tuple: A tuple containing the two parts of the signature (r, s).
            - r (int): The first part of the DSA signature.
            - s (int): The second part of the DSA signature.

    Example:
        > r, s = dsa_signature(message=123456789, g=12345, k=6789, p=103687, q=1571, x=453)
        R Signature: 190
        Hashed Message (hex): 24efa2ce903882c8124b5a4834282b089ce39359
        S Signature: 800
        Signature (r, s): (190, 800)
        190 800
    """
    r = pow(g, k, p) % q
    print(f"\nR Signature: {r}")

    k_inv = pow(k, -1, q)
    hash_message_hex = hash_message(message)
    print(f"Hashed Message (hex): {hash_message_hex}")
    hashed_message = int(hash_message_hex, 16)

    s = (k_inv * (hashed_message + x * r)) % q
    print(f"S Signature: {s}")
    print(f"Signature (r, s): {r, s}")
    return (r, s)

def dsa_verify(message: int, r: int, s: int, p: int, q: int, y: int, g: int) -> bool:
    """
    Verifies a DSA signature for a given message.

    This function verifies the authenticity of a DSA signature by checking if the computed
    value `v` equals the value `r` from the signature. The verification process uses the
    signature components `(r, s)` and the public key `y` along with the DSA parameters
    `p`, `q`, and `g`.

    The steps of verification are as follows:
    - Compute `w = s^(-1) mod q`
    - Compute `u1 = (hashed_message * w) % q`
    - Compute `u2 = (r * w) % q`
    - Compute `v = ((g^u1 * y^u2) % p) % q`
    - The signature is valid if and only if `v == r` and `r != 0` and `s != 0`.

    Parameters:
        message (int): The original message that was signed.
        r (int): The first part of the DSA signature.
        s (int): The second part of the DSA signature.
        p (int): The prime number used in DSA.
        q (int): The prime divisor of p-1.
        y (int): The public key of the signer.
        g (int): The generator used in DSA.

    Returns:
        bool: True if the signature is valid, False if it is invalid.

    Example (from a sample run):
        > dsa_verify(message, r, s, p, q, y, g)
        w is 442394850945470038515099568836656785042404726249
        u1 is 769589615002557493471037413659797693707918205528
        u2 is 887498085411400194425698233401903972105621053917
        v is 1105537019561117122081292895594178549579681815970
        True
    """
    w = pow(s, -1, q)
    print(f"w is {w}")
    hashed_message_hex = hash_message(message)
    hashed_message = int(hashed_message_hex, 16)

    u1 =  (hashed_message * w) % q
    print(f"u1 is {u1}")
    u2 = (r * w) % q
    print(f"u2 is {u2}")

    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    print(f"v is {v}")
    return r != 0 and s != 0 and v == r

if __name__ == "__main__":
    test_large_prime()
    test_small_prime()
    p, q, g = dsa_global_keys()
    x, y, k = dsa_keys_and_num(g, p, q)
    message = 582346829057612
    r, s = dsa_signature(message, g, k, p, q, x)

    print(f"Verify Signature")
    print(f"Signature Valid? {dsa_verify(message, r, s, p, q, y, g)}")
    r2, s2 = dsa_signature(message=123456789, g=12345, k=6789, p=103687, q=1571, x=453)
    print(r2, s2)
