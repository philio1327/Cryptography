import random

def mod_inverse(a: int, q: int) -> int:
    """
    Compute modular inverse of 'a' modulo 'q'

    Uses the Extended Euclidean Algorithm to find an integer such that:
    (a * x) % q = 1

    Parameters:
    - a (int): The integer for which the inverse is needed.
    - q (int): The modulus

    Returns: int
    """
    m0, x0, x1 = q, 0, 1
    while a > 1:
        # q is quotient
        quotient = a // q
        m, a = a % q, q
        q = m
        x0, x1 = x1 - quotient * x0, x0
    if x1 < 0:
        x1 += m0
    return x1


def generate_keys(q: int, alpha: int) -> ((int, int, int), int):
    """
    Generate public and private keys for the ElGamal encryption scheme.

    This function generates a random private key 'x_a' and calculates the corresponding
    public key component 'y_a' using the given prime modulus 'q' and primitive root 'alpha'.
    The public key is returned as a tuple (q, alpha, y_a), and the private key as 'x_a'.

    Parameters:
    - q (int): A large prime modulus.
    - alpha (int): A primitive root of 'q'.

    Returns:
    - tuple: A tuple containing:
        - public_key (tuple): The public key as (q, alpha, y_a).
        - x_a (int): The private key, a randomly chosen integer such that 1 < x_a < q - 1.
    """
    # Step 1: Generate a random private key x_a
    x_a = random.randint(2, q - 2)  # Private key

    # Step 2: Compute the public key component Y_A
    y_a = pow(alpha, x_a, q)  # y_a = alpha^x_a mod q

    # Public key is (q, alpha, y_a), private key is x_a
    return (q, alpha, y_a), x_a


def encrypt(public_key: (int, int, int), m: int) -> (int, int):
    """
    Encrypt a message 'm' using the ElGamal encryption scheme and a given public key.

    This function encrypts the message 'm' by generating a random integer 'k' and computing
    a one-time encryption key 'K'. It returns a ciphertext pair (C1, C2) where:
    - C1 = alpha^k mod q
    - C2 = (K * m) mod q, with K as the shared key computed as (y_a)^k mod q.

    Parameters:
    - public_key (tuple): A tuple representing the public key (q, alpha, y_a) where:
        - q (int): The prime modulus.
        - alpha (int): The primitive root of q.
        - y_a (int): The public key component y_a = alpha^x_a mod q.
    - m (int): The message to encrypt, represented as an integer in the range 0 <= m < q.

    Returns:
    - tuple: A tuple containing the ciphertext components (C1, C2), where:
        - C1 (int): The value alpha^k mod q.
        - C2 (int): The encrypted message as (K * m) mod q.
    """
    q, alpha, y_a = public_key

    # Step 1: Choose a random integer k
    k = random.randint(1, q - 2)

    # Step 2: Compute the one-time key K = (Y_A)^k mod q
    K = pow(y_a, k, q)

    # Step 3: Compute C1 and C2
    C1 = pow(alpha, k, q)
    C2 = (K * m) % q

    # Return ciphertext as the pair (C1, C2)
    return C1, C2

def encrypt_set_k(public_key: (int, int, int), m: int, k: int) -> (int, int):
    """
    Encrypt a message 'm' using the ElGamal encryption scheme with a specified value of 'k'.

    This function encrypts the message 'm' with a given random integer 'k', allowing control
    over the 'k' parameter instead of choosing it randomly. It returns a ciphertext pair (C1, C2),
    where:
    - C1 = alpha^k mod q
    - C2 = (K * m) mod q, with K as the shared key computed as (y_a)^k mod q.

    Parameters:
    - public_key (tuple): A tuple representing the public key (q, alpha, y_a) where:
        - q (int): The prime modulus.
        - alpha (int): The primitive root of q.
        - y_a (int): The public key component y_a = alpha^x_a mod q.
    - m (int): The message to encrypt, represented as an integer in the range 0 <= m < q.
    - k (int): The integer to use as the random encryption key, typically in the range 1 <= k < q - 1.

    Returns:
    - tuple: A tuple containing the ciphertext components (C1, C2), where:
        - C1 (int): The value alpha^k mod q.
        - C2 (int): The encrypted message as (K * m) mod q.
    """
    q, alpha, y_a = public_key
    K = pow(y_a, k, q)

    C1 = pow(alpha, k, q)
    C2 = (K * m) % q
    return C1, C2


def decrypt(private_key: int, q: int, C1: int, C2:int) -> int:
    """
    Decrypt a ciphertext pair (C1, C2) using the ElGamal decryption scheme.

    This function decrypts the ciphertext components (C1, C2) to recover the original message 'm'.
    It first computes the shared key 'K' using the private key, then finds the modular inverse
    of 'K' to retrieve 'm' as (C2 * K_inv) % q.

    Parameters:
    - private_key (int): The private key 'x_a' of the receiver, used to compute the decryption key.
    - q (int): The prime modulus used in the encryption.
    - C1 (int): The first component of the ciphertext, computed as alpha^k mod q.
    - C2 (int): The second component of the ciphertext, representing (K * m) mod q.

    Returns:
    - int: The decrypted message 'm', an integer in the range 0 <= m < q.
    """
    # Step 1: Recover the key K = (C1)^X_A mod q
    K = pow(C1, private_key, q)

    # Step 2: Compute modular inverse of K
    K_inv = mod_inverse(K, q)

    # Step 3: Recover the message M = (C2 * K_inv) % q
    m = (C2 * K_inv) % q

    return m

def compute_m2_from_m1(m1: int, c_21: int, c_22: int, q: int) -> int:
    """
    Compute the value of a second message 'm2' given an initial message 'm1' and its ciphertext components.

    Using the relationship between two messages encrypted with the same random integer 'k', this function
    calculates 'm2' based on the known values of 'm1' and the ciphertext components (c_21, c_22) of 'm2'.

    Parameters:
    - m1 (int): The first known message in integer form.
    - c_21 (int): The first component of the ciphertext for 'm2' (C1 for m2), computed as alpha^k mod q.
    - c_22 (int): The second component of the ciphertext for 'm2' (C2 for m2), representing (K * m2) mod q.
    - q (int): The prime modulus used in the encryption process.

    Returns:
    - int: The computed message 'm2', an integer in the range 0 <= m2 < q.
    """
    c_c21inv = mod_inverse(c_21, q)
    return (c_c21inv * c_22 * m1) % q

if __name__ == "__main__":
    q = 89
    alpha = 13
    m1 = 72

    print(f"Prime Number q: {q}")
    print(f"Primitive root alpha: {alpha}")
    print(f"Message m1: {m1}")


    # Generate keys
    public_key, private_key = generate_keys(q, alpha)
    print(f"Keys are: {public_key, private_key}")

    # Encrypt the message m1
    C1, C2 = encrypt(public_key, m1)
    print(f"Ciphertext: (C1, C2) = ({C1}, {C2})")

    # Decrypt the message to verify
    decrypted_message = decrypt(private_key, q, C1, C2)
    print(f"Decrypted message: {decrypted_message}")

    # To find m2 given m1 and the same k:
    # Just repeat the encryption for m2 with the same k.
    m2 = random.randint(0, q-1)
    C1_m2, C2_m2 = encrypt_set_k(public_key, m2, 41)
    print(f"Additional Message to Encrypt: {m2}")
    print(f"Ciphertext: (C1, C2) = {C1_m2, C2_m2}")
    # Decrypt m2
    decrypted_m2 = decrypt(private_key, q, C1_m2, C2_m2)

    print("Let's find m2 if we know that m1=72 and k=41")
    print(f"Compute C1 (both C1_1 and C1_2): {pow(alpha, 41, q)}")
    print(f"Compute C2_1")
    print(f"Y_A public key component is: {public_key[2]}")
    K = pow(public_key[2], 41, q)
    print(f"One-Time Key K = Y_A ** k mod q: {K}")
    C2_1 = (K*m1) % q
    print(f"C2_1 = K x m1 mod q: {C2_1}")
    print(f"C2_2 we have: {C2_m2}")
    print(f"m2 is ((C2_1 inv) * C2_2 * m1) mod q")
    m2_decrypted = (mod_inverse(C2_1, q) * C2_m2 * m1) % q
    print(f"m2 decrypted via equation is: {m2_decrypted}")
    print(f"Check original m2: {m2}")


