import random
import time
from sympy import isprime
from functools import lru_cache, cache
from cryptography.hazmat.primitives.asymmetric import rsa
from assignment_3_q2_8191716 import miller_rabin, run_n_times

def generate_n_bit_prime(n: int) -> int:
    """
    Generates a prime number of `n` bits using RSA key generation.

    Parameters:
        n (int): The number of bits for the prime number.

    Returns:
        int: A prime number with the specified bit length `n`.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=n * 2)

    # Extract primes
    p = key.private_numbers().p
    q = key.private_numbers().q

    # Check if either matches the required bit size
    if p.bit_length() == n:
        return p
    elif q.bit_length() == n:
        return q
    else:
        # If the bit length isn't exact, regenerate (unlikely but possible)
        return generate_n_bit_prime(n)

def generate_n_bit_random_prime(n: int) -> int:
    """
    Generates a random prime number with exactly `n` bits using probabilistic primality testing.

    Parameters:
        n (int): The desired bit length of the generated prime.

    Returns:
        int: A prime number with exactly `n` bits.
    """
    cand_prime = random.randint(2**(n-1), 2**n - 1)
    test = run_n_times(10, cand_prime)

    while cand_prime % 2 == 0 or cand_prime % 3 == 0 or cand_prime % 5 == 0 or cand_prime % 7 == 0 or (False in test):
        cand_prime = random.randint(2**159, 2**160 - 1)
        test = run_n_times(10, cand_prime)
    return cand_prime


def generate_ab(p: int) -> (int, int):
    """
    Randomly generates curve parameters `a` and `b` for an elliptic curve over a finite field.
    The parameters satisfy the elliptic curve condition to ensure a valid curve.

    Parameters:
        p (int): A prime number defining the finite field F_p.

    Returns:
        tuple: A pair of integers `(a, b)` where:
            - `a` is the coefficient for the x^3 term in the elliptic curve equation.
            - `b` is the constant term in the elliptic curve equation.
    """
    while True:
        a = random.randint(0, p-1)
        b = random.randint(0, p-1)
        if (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p != 0:
            return a, b

def is_quadratic_residue(y2, p):
    """
    Determines whether a given number y2 is a quadratic residue modulo p.
    A number y2 is a quadratic residue modulo p if there exists an integer x
    such that x^2 = y^2 mod p.

    Args:
        y2 (int): The number to test for being a quadratic residue modulo p.
        p (int): A prime number defining the modulo.

    Returns:
        bool: `True` if y2 is a quadratic residue modulo p, otherwise `False`.
    """
    return pow(y2, (p - 1) // 2, p) == 1

def generate_private_key(p: int) -> int:
    """
       Generates a random private key.
       The private key is a random integer selected from the range [2, p-2], where `p` is a large prime number.

       Parameters:
           p (int): A large prime number.

       Returns:
           int: A randomly selected private key in the range [2, p-2].
    """
    return random.randint(2, p-2)

def generate_base_point(a: int, b: int, p: int) -> (int, int):
    """
    Generates a base point (G) for an elliptic curve defined by the equation:
        y^2 = x^3 + ax + b (mod p)
    The base point is a point on the elliptic curve that satisfies the equation for some values of x and y.

    Parameters:
        a (int): The coefficient `a` in the elliptic curve equation.
        b (int): The coefficient `b` in the elliptic curve equation.
        p (int): A prime number used as the modulus for the elliptic curve.

    Returns:
        tuple: A tuple (x, y) representing a valid base point on the elliptic curve.

    Raises:
        ValueError: If no valid base point can be found.
    """
    for x in range(p):
        rhs = (x**3 + a * x + b) % p
        for y in range(p):
            if pow(y, 2, p) == rhs:
                return x, y
    raise ValueError("No valid base point found.")


def point_double(P: (int, int), a: int, p: int) -> (int, int):
    """
    Doubles a point P on an elliptic curve defined by the equation:
        y^2 = x^3 + ax + b (mod p)

    This function computes the point P + P (i.e., doubling the point P) on the elliptic curve using the
    point doubling formula.

    Parameters:
          P (tuple): A tuple (x1, y1) representing a point on the elliptic curve, or (None, None) if P is the point at infinity.
          a (int): The coefficient `a` in the elliptic curve equation.
          p (int): The prime modulus used for the elliptic curve.

    Returns:
          tuple: A tuple (x3, y3) representing the doubled point P, or (None, None) if the result is the point at infinity.
    """
    if P == (None, None):  # Point at infinity
        return (None, None)
    x1, y1 = P[0], P[1]

    if y1 == 0:  # Tangent is vertical
        return (None, None)

    lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    x3 = (lam * lam - 2 * x1) % p
    y3 = (lam * (x1 - x3) - y1) % p

    return (x3, y3)

def point_add(P: (int, int), Q: (int, int), a: int, p: int) -> (int, int):
    """
    Adds two points P and Q on an elliptic curve defined by the equation:
        y^2 = x^3 + ax + b (mod p)

    This function implements both point addition and point doubling on an elliptic curve. If the points
    are the same (P == Q), the function uses point doubling. If the points are distinct, it computes
    the sum of the points.

    Parameters:
        P (tuple): A tuple (x1, y1) representing the first point on the elliptic curve, or (None, None)
                   if P is the point at infinity.
        Q (tuple): A tuple (x2, y2) representing the second point on the elliptic curve, or (None, None)
                   if Q is the point at infinity.
        a (int): The coefficient `a` in the elliptic curve equation.
        p (int): The prime modulus used for the elliptic curve.

    Returns:
        tuple: A tuple (x3, y3) representing the result of the point addition P + Q, or (None, None)
               if the result is the point at infinity.
    """
    if P == (None, None):  # Point at infinity
        return Q
    if Q == (None, None):  # Point at infinity
        return P
    x1, y1 = P[0], P[1]
    x2, y2 = Q[0], Q[1]

    if x1 == x2 and y1 != y2:
        return (None, None)  # Result is point at infinity

    if P == Q:  # Point doubling
        return point_double(P, a, p)

    # Regular point addition
    lam = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p

    return (x3, y3)


def scalar_mult(k: int, P: (int, int), a: int, p: int) -> (int, int):
    """
    Performs scalar multiplication on an elliptic curve using the double-and-add method.

    Scalar multiplication is the process of multiplying a point P by a scalar k on an elliptic curve.
    This is done using the double-and-add algorithm, which is an efficient method to compute k * P.

    Parameters:
        k (int): The scalar to multiply the point P by.
        P (tuple): The point (x, y) on the elliptic curve to be multiplied by k.
        a (int): The coefficient `a` in the elliptic curve equation y^2 = x^3 + ax + b (mod p).
        p (int): The prime modulus used for the elliptic curve.

    Returns:
        tuple: The resulting point (x, y) after multiplying P by k, or (None, None) if the result is the point at infinity.
    """
    R = (None, None)  # Initialize R as the point at infinity
    Q = P             # Copy of P to avoid modifying the input

    while k > 0:
        if k & 1:  # If the current bit of k is 1
            R = point_add(R, Q, a, p)
        Q = point_double(Q, a, p)  # Always double Q
        k >>= 1  # Right-shift k by 1 bit

    return R
############################
# New Optimizations for ECDH
############################
@lru_cache(None)
def point_double_jacobian(P: (int, int, int), a: int, p: int) -> (int, int, int):
    """
    Performs point doubling on an elliptic curve in Jacobian coordinates.

    This function computes the result of doubling a point P = (X1, Y1, Z1) on the elliptic curve
    y^2 = x^3 + ax + b (mod p) using Jacobian coordinates. Jacobian coordinates are a projective
    coordinate system that allows for more efficient computation of elliptic curve operations.

    The point doubling operation is performed using the following formulas:
        S = 4 * X1 * Y1^2
        M = 3 * X1^2 + a * Z1^2
        X3 = M^2 - 2 * S
        Y3 = M * (S - X3) - 8 * Y1^4
        Z3 = 2 * Y1 * Z1

    Args:
        P (tuple): A point (X1, Y1, Z1) on the elliptic curve in Jacobian coordinates.
            - X1 (int): The X coordinate of the point.
            - Y1 (int): The Y coordinate of the point.
            - Z1 (int): The Z coordinate of the point (projective coordinate).
        a (int): The coefficient `a` in the elliptic curve equation y^2 = x^3 + ax + b (mod p).
        p (int): The prime modulus used for the elliptic curve, ensuring calculations are done modulo p.

    Returns:
        tuple: The resulting point (X3, Y3, Z3) after doubling the point P.
               - X3 (int): The X coordinate of the doubled point.
               - Y3 (int): The Y coordinate of the doubled point.
               - Z3 (int): The Z coordinate of the doubled point.
    """
    X1, Y1, Z1 = P

    if Z1 == 0 or Y1 == 0:
        return (0, 0, 0)  # Point at infinity

    S = (4 * X1 * Y1 * Y1) % p
    M = (3 * X1 * X1 + a * Z1 * Z1) % p
    X3 = (M * M - 2 * S) % p
    Y3 = (M * (S - X3) - 8 * Y1 * Y1 * Y1 * Y1) % p
    Z3 = (2 * Y1 * Z1) % p

    return (X3, Y3, Z3)

@lru_cache(None)
def point_add_jacobian(P: (int, int, int), Q: (int, int, int), a: int, p: int) -> (int, int, int):
    """
    Performs elliptic curve point addition in Jacobian coordinates.

    This function computes the result of adding two points P and Q on the elliptic curve
    y^2 = x^3 + ax + b (mod p) using Jacobian coordinates. Jacobian coordinates allow
    for more efficient elliptic curve operations by avoiding expensive division operations.

    The point addition operation is performed using the following formulas:
        U1 = X1 * Z2^2
        U2 = X2 * Z1^2
        S1 = Y1 * Z2^3
        S2 = Y2 * Z1^3
        H = U2 - U1
        R = S2 - S1
        H2 = H^2
        H3 = H * H2
        U1H2 = U1 * H2
        X3 = R^2 - H3 - 2 * U1H2
        Y3 = R * (U1H2 - X3) - S1 * H3
        Z3 = H * Z1 * Z2

    Parameters:
        P (tuple): A point (X1, Y1, Z1) on the elliptic curve in Jacobian coordinates.
            - X1 (int): The X coordinate of the first point.
            - Y1 (int): The Y coordinate of the first point.
            - Z1 (int): The Z coordinate of the first point (projective coordinate).
        Q (tuple): A point (X2, Y2, Z2) on the elliptic curve in Jacobian coordinates.
            - X2 (int): The X coordinate of the second point.
            - Y2 (int): The Y coordinate of the second point.
            - Z2 (int): The Z coordinate of the second point (projective coordinate).
        a (int): The coefficient `a` in the elliptic curve equation y^2 = x^3 + ax + b (mod p).
        p (int): The prime modulus used for the elliptic curve, ensuring calculations are done modulo p.

    Returns:
        tuple: The resulting point (X3, Y3, Z3) after adding points P and Q.
               - X3 (int): The X coordinate of the resulting point.
               - Y3 (int): The Y coordinate of the resulting point.
               - Z3 (int): The Z coordinate of the resulting point.
    """
    X1, Y1, Z1 = P
    X2, Y2, Z2 = Q

    if Z1 == 0:
        return Q
    if Z2 == 0:
        return P

    U1 = (X1 * pow(Z2, 2, p)) % p
    U2 = (X2 * pow(Z1, 2, p)) % p
    S1 = (Y1 * pow(Z2, 3, p)) % p
    S2 = (Y2 * pow(Z1, 3, p)) % p

    if U1 == U2:
        if S1 != S2:
            return (0, 0, 0)  # Point at infinity
        else:
            return point_double_jacobian(P, a, p)

    H = (U2 - U1) % p
    R = (S2 - S1) % p
    H2 = (H * H) % p
    H3 = (H * H2) % p
    U1H2 = (U1 * H2) % p

    X3 = (R * R - H3 - 2 * U1H2) % p
    Y3 = (R * (U1H2 - X3) - S1 * H3) % p
    Z3 = (H * Z1 * Z2) % p

    return (X3, Y3, Z3)

@lru_cache(None)
def scalar_mult_jacobian(k: int, P: (int, int, int), a: int, p: int) -> (int, int, int):
    """
    Perform scalar multiplication of a point on an elliptic curve using Jacobian coordinates.

    This function computes the scalar multiplication of a point P by an integer k on the elliptic
    curve y^2 = x^3 + ax + b (mod p) using Jacobian projective coordinates. The algorithm utilizes
    a binary method (double-and-add) to efficiently compute the result, which reduces the need for
    costly modular inversions in comparison to the affine coordinate system.

    The scalar multiplication works by iterating through the binary representation of the scalar k,
    and for each bit:
        - If the bit is 1, add the current point to the result.
        - Double the current point at each step.

    Parameters:
        k (int): The scalar by which to multiply the point P.
        P (tuple): A point (X1, Y1, Z1) on the elliptic curve in Jacobian coordinates.
            - X1 (int): The X coordinate of the point.
            - Y1 (int): The Y coordinate of the point.
            - Z1 (int): The Z coordinate of the point (projective coordinate).
        a (int): The coefficient `a` in the elliptic curve equation y^2 = x^3 + ax + b (mod p).
        p (int): The prime modulus used for elliptic curve operations.

    Returns:
        tuple: The resulting point (X, Y, Z) after performing scalar multiplication.
               - X (int): The X coordinate of the resulting point.
               - Y (int): The Y coordinate of the resulting point.
               - Z (int): The Z coordinate of the resulting point.
    """

    R0 = (0, 0, 0)  # Point at infinity in Jacobian coordinates
    R1 = P           # Initial point

    for bit in bin(k)[2:]:
        if bit == '0':
            R1 = point_add_jacobian(R0, R1, a, p)
            R0 = point_double_jacobian(R0, a, p)
        else:
            R0 = point_add_jacobian(R0, R1, a, p)
            R1 = point_double_jacobian(R1, a, p)

    return R0

@lru_cache(None)
def jacobian_to_affine(P: (int, int, int), p: int) -> (int, int):
    """
    Convert a point from Jacobian coordinates to affine coordinates.

    This function converts a point P represented in Jacobian projective coordinates
    (X, Y, Z) to affine coordinates (x, y) on an elliptic curve. In Jacobian coordinates,
    the point is represented as (X, Y, Z), where Z is a projective coordinate that
    eliminates the need for modular inversions when performing operations such as
    scalar multiplication. To convert to affine coordinates, we compute the inverse of Z
    modulo p and apply it to X and Y.

    Parameters:
        P (tuple): A point (X, Y, Z) on the elliptic curve in Jacobian coordinates.
            - X (int): The X coordinate of the point in Jacobian coordinates.
            - Y (int): The Y coordinate of the point in Jacobian coordinates.
            - Z (int): The Z coordinate of the point in Jacobian coordinates.
        p (int): The prime modulus used for elliptic curve operations.

    Returns:
        tuple: The point in affine coordinates (x, y) if the point is valid.
            - x (int): The X coordinate of the point in affine coordinates.
            - y (int): The Y coordinate of the point in affine coordinates.
        If the input point is the point at infinity (Z == 0), the function returns (None, None).
    """

    X, Y, Z = P
    if Z == 0:
        return (None, None)
    Z_inv = pow(Z, -1, p)
    Z_inv2 = (Z_inv * Z_inv) % p
    Z_inv3 = (Z_inv2 * Z_inv) % p
    x = (X * Z_inv2) % p
    y = (Y * Z_inv3) % p
    return (x, y)

###################
# END Optimizations
###################

def generate_safe_prime(bits: int) -> (int, int):
    """
    Generate a safe prime and its corresponding prime q.

    A safe prime is a prime number p such that p = 2 * q + 1, where q is also prime.
    This function generates a random value for q, ensures it's odd, checks if q is prime,
    and then computes p as 2 * q + 1. The process repeats until both q and p are prime.

    Parameters:
        bits (int): The number of bits for the prime q. The corresponding safe prime p
                    will be calculated as 2 * q + 1.

    Returns:
        tuple: A tuple containing two integers (p, q), where:
            - p is the safe prime (2 * q + 1).
            - q is the prime used to generate p.

    Prints:
        If the function tries 10,000 primes without finding a safe prime,
        it prints the number of attempts made so far.
    """
    count = 0
    while True:
        count += 1
        q = random.getrandbits(bits - 1)
        q |= 1  # Ensure q is odd
        if count % 10_000 == 0:
            print(f"Tried {count} primes")
        if isprime(q):
            p = 2 * q + 1
            if isprime(p):
                return p, q
# For DH Implementation
def find_generator(p: int, q: int) -> int:
    """
    Find a generator for the multiplicative group of integers modulo p.

    A generator g for a prime modulus p is a number such that the powers of g
    modulo p generate all numbers in the multiplicative group modulo p. Specifically,
    this function finds a number g such that g^2 mod p != 1 and g^q mod p == 1, where
    q is a prime divisor of p-1.

    Parameters:
        p (int): A prime number that defines the modulus for the multiplicative group.
        q (int): A prime divisor of p-1 used to check the generator's properties.

    Returns:
        int: A generator g such that:
            - g^2 mod p != 1 (to ensure it's not trivial).
            - g^q mod p == 1 (ensuring the order of g is q).
    """
    while True:
        g = random.randint(2, p - 2)
        # Check that g^2 mod p != 1 and g^q mod p == 1
        if pow(g, 2, p) != 1 and pow(g, q, p) == 1:
            return g

if __name__ == "__main__":
    # prime = generate_n_bit_random_prime(160)
    # a, b = generate_ab(prime)

    # Curve parameter format (p, a, b, Gx, Gy)
    # SECP160R1 (P-160) curve parameters

    secp160 = ("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
               "64210519e59c80e70fa7e9ab72243049feb8f5018b4e0e7b54e3a8f", "4A96B5688EF57328464A62A0EC5AB1AE8D9750280B63AA43EF7D906A",
               "6A91174076B1E6F1A5DF1A4D4E68A93D6CA3B6F2BBDC140E5BFB5620")

    # Brainpool P160r1 parameters

    brainpool = ('E95E4A5F737059DC60DFC7AD95B3D8139515620F', '340E7BE2A280EB74E2BE61BADA745D97E8F7C300',
                '1E589A8595423412134FAA2DBDEC95C8D8675E58', 'BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3',
                '1667CB477A1A8EC338F94741669C976316DA6321')

    # SECP160K1 curve parameters

    secp160k1 = ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF", "0000000000000000000000000000000000000000",
                 "0000000000000000000000000000000000000007", "4E8F3F72DFA3B3B3B3A1F97A3A83F257F61719F4F4B6D6D8A6DAA80D",
                 "5F1FF7883F3136C09EE2A2D081F31D31355F2E3F1D1A3C5519FC5A")

    # NIST P-160 curve parameters

    nist = ("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
            "64210519e59c80e70fa7e9ab72243049feb8f5018b4e0e7b54e3a8f", "4A96B5688EF57328464A62A0EC5AB1AE8D9750280B63AA43EF7D906A",
            "6A91174076B1E6F1A5DF1A4D4E68A93D6CA3B6F2BBDC140E5BFB5620")

    choices = {secp160: "SECP160R1 (P-160)", brainpool: "Brainpool P160r1", secp160k1: "SECP160K1", nist: "NIST P-160"}

    selected_curve = random.choice(list(choices))
    selected_curve_name = choices[selected_curve]

    print(f"Elliptic Curve Selected was: {selected_curve_name}")


    # Convert all to integers
    prime = int(selected_curve[0], 16)
    a = int(selected_curve[1], 16)
    b = int(selected_curve[2], 16)
    Gx = int(selected_curve[3], 16)
    Gy = int(selected_curve[4], 16)

    print(f"Prime Number: {prime}")
    print(f"Elliptic Curve a, b: {a, b}")
    # print(f"Generate Our Base Point (x,y) that satisfies: y^2 mod p = (x^3 + ax + b) mod p")
    # G = generate_base_point(a, b, prime)
    G = (Gx, Gy, 1)
    print(f"Generated (x, y, z): {(Gx, Gy, 1)}")
    d_a, d_b = generate_private_key(prime), generate_private_key(prime)
    print(f"Alice's Private Key: {d_a}")
    print(f"Bob's Private Key: {d_b}")

    # Compute public keys using optimized scalar multiplication
    P_A_jacobian = scalar_mult_jacobian(d_a, G, a, prime)
    P_B_jacobian = scalar_mult_jacobian(d_b, G, a, prime)
    P_A = jacobian_to_affine(P_A_jacobian, prime)
    P_B = jacobian_to_affine(P_B_jacobian, prime)
    print(f"Alice's Public Key P_A: {P_A}")
    print(f"Bob's Public Key P_B: {P_B}")

    # Compute shared secret using optimized scalar multiplication
    time_start = time.perf_counter_ns()
    # Convert P_B to Jacobian coordinates for scalar multiplication
    P_B_jacobian = (P_B[0], P_B[1], 1)
    S_A_jacobian = scalar_mult_jacobian(d_a, P_B_jacobian, a, prime)
    S_A = jacobian_to_affine(S_A_jacobian, prime)

    # Convert P_A to Jacobian coordinates for scalar multiplication
    P_A_jacobian = (P_A[0], P_A[1], 1)
    S_B_jacobian = scalar_mult_jacobian(d_b, P_A_jacobian, a, prime)
    S_B = jacobian_to_affine(S_B_jacobian, prime)
    time_end = time.perf_counter_ns()

    print(f"Alice's Shared Secret S_A: {S_A}")
    print(f"Bob's Shared Secret S_B: {S_B}")
    print(f"ECDH Shared Secret Key Time: {time_end - time_start} ns")


    #########################################
    # Non-Jacobian Optimization Implementation
    #########################################
    P_A = scalar_mult(d_a, G, a, prime)
    P_B = scalar_mult(d_b, G, a, prime)
    print(f"\nNon-Jacobian Implementation\n")
    print(f"Alice's public key P_A: {P_A}")
    print(f"Bob's public key P_B: {P_B}")

    time_start1 = time.perf_counter_ns()
    S_A = scalar_mult(d_a, P_B, a, prime)
    S_B = scalar_mult(d_b, P_A, a, prime)
    print(f"Alice's Shared Secret d_a * P_B: {S_A}")
    print(f"Bob's Shared Secret d_b * P_A: {S_B}")
    time_end1 = time.perf_counter_ns()

    ##########################################
    #
    ##########################################
    print("Now to implement DH")

    p_1024, q_1024 = generate_safe_prime(1024)
    a_key = d_a
    b_key = d_b
    generator = find_generator(p_1024, q_1024)

    dh_start = time.perf_counter_ns()
    pub_key_a = pow(generator, a_key, p_1024)
    pub_key_b = pow(generator, b_key, p_1024)
    print(f"DH Prime is: {p_1024}")
    print("Alice and Bob use the same private keys as before")
    print(f"Alice's public key P_A is: {pub_key_a}")
    print(f"Bob's public key P_B is: {pub_key_b}")


    shared_alice = pow(pub_key_b, a_key, p_1024)
    shared_bob = pow(pub_key_a, b_key, p_1024)
    print(f"Alice computes shared key s=B**a_key mod p: {shared_alice}")
    print(f"Bob computes shared key s=A**b mod p: {shared_bob}")
    dh_end = time.perf_counter_ns()

    assert shared_alice == shared_bob, "Shared secrets should match"

    print(f"ECDH Shared Secret Key Time: {time_end - time_start} ns")
    print(f"Non-Jacobian ECDH Shared Secret Key Time: {time_end1 - time_start1} ns")
    print(f"DH Shared Secret Key Time: {dh_end - dh_start} ns")