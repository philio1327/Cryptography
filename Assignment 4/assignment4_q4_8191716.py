####################################################################################################
#  File Name: assignment4_q4_8191716.py                                                            #
#  Description: Implement DSA                                                                      #
#  Usage: Run from Pycharm or any other IDE, or                                                    #
#         Terminal: python assignment4_q4_8191716.py                                               #
#  Author: Philip Anderegg                                                                         #
#  Created On: 23-11-2024                                                                          #
#  Last Modified On: 26-11-2024                                                                    #
#  Student Number: 8191716                                                                         #
#  Course Name: Cryptography                                                                       #
#  Course Code: CSI 4108                                                                           #
#  Professor: Dr. Carlisle Adams                                                                   #
#  Due Date: Friday, November 29th, 2024                                                           #
####################################################################################################
import timeit
from assignment4_q2_8191716 import dsa_signature
from math import isqrt

def brute_force_x(p: int, g: int, a: int) -> int:
    """
    Brute force method to find the discrete logarithm (x) such that:
    A = y = g^x mod p, where g is a generator modulo p and A = a is the known value.

    Parameters:
    - p (int): The prime modulus p used in the modular arithmetic.
    - g (int): The generator (or base) g used in the modular exponentiation.
    - a (int): The value for which we are trying to find the discrete logarithm (x), i.e., g^x mod p = a.

    Returns:
    - int: The value of x such that g^x ≡ a (mod p). If no solution is found, the function will return `None`.

    This function performs a brute-force search over all possible values of x in the range [0, p-1] and checks if
    g^x modulo p equals a. This method has time complexity O(p) and is feasible only for small values of p.

    Example:
        > brute_force_x(23, 5, 8)
        6

    Notes:
        - This function assumes that `p` is a large prime number, `g` is a generator mod p, and `a` is a valid result
          of g^x mod p for some integer x.
        - It is not optimized for large primes and should be used with caution for large inputs, as it may take
          an impractical amount of time to compute.
    """
    # Note that A = y = g^x mod p
    for i in range(p):
        y = pow(g, i, p)
        if y == a:
            return i

def baby_step_giant_step(p: int, g: int, a: int) -> int:
    """
    Solve the discrete logarithm problem g^x ≡ a (mod p) using the Baby-Step Giant-Step algorithm.

    The algorithm is designed to find the integer x such that g^x ≡ a (mod p), where g is a known
    generator modulo a prime p, and a is the known value for which we need to find x. The algorithm
    uses an efficient method based on precomputing baby steps and then performing giant steps to find the solution.

    Parameters:
    - p (int): The prime modulus p used in the modular arithmetic.
    - g (int): The generator (or base) g used in the modular exponentiation.
    - a (int): The value for which we are trying to find the discrete logarithm (x), i.e., g^x ≡ a (mod p).

    Returns:
    - int: The value of x such that g^x ≡ a (mod p). If no solution is found, the function will return `None`.

    The algorithm works by:
    1. Precomputing baby steps for values of j from 0 to m-1, where m is approximately the square root of p.
    2. Computing giant steps by iteratively multiplying the known value `a` by powers of g^(-m) modulo p.
    3. Checking for a match between giant steps and precomputed baby steps to find the value of x.

    The time complexity of this algorithm is O(sqrt(p)), which is a significant improvement over brute-force methods!

    Example:
        > baby_step_giant_step(23, 5, 8)
        6

    Notes:
        - This algorithm assumes that p is a prime number and g is a generator modulo p.
        - The method is efficient for smaller primes and can be used in cryptographic applications, such as solving discrete logarithms in groups.
    """
    # Step 1: Precompute Baby Steps
    m = isqrt(p) + 1  # Ceiling of sqrt(p)
    baby_steps = {}

    for j in range(m):
        baby_step = pow(g, j, p) # compute g^j mod p
        baby_steps[baby_step] = j

    # Step 2: Compute Giant Steps
    g_exp_m = pow(g, m, p)
    g_m = pow(g_exp_m, -1, p)# g^(-m) mod p in 2 steps
    giant_step = a

    for i in range(m):
        if giant_step in baby_steps:
            j = baby_steps[giant_step]
            return i * m + j  # Solution x = i * m + j
        giant_step = (giant_step * g_m) % p

    return None  # No solution found

def new_vals(val1: int, val2: int, val3: int, N: int, n: int, alpha: int, beta: int) -> (int, int, int):
    """
    Helper function for Pollard's Rho algorithm that updates the values
    of val1, val2, and val3 based on the state of val1 modulo 3.

    The function applies different transformations to the values val1,
    val2, and val3 depending on the value of val1 modulo 3. This is part
    of the cycle detection process in Pollard's Rho algorithm for factorization.

    Parameters:
    - val1 (int): The first value in the triplet, representing the current state.
    - val2 (int): The second value in the triplet, typically related to the exponent.
    - val3 (int): The third value in the triplet, also related to the exponent.
    - N (int): The modulus used for performing the modular arithmetic.
    - n (int): The modulus used for the secondary computations related to the exponents.
    - alpha (int): A constant used for updating val1 in case 1.
    - beta (int): A constant used for updating val1 in case 2.

    Returns:
    - tuple: A tuple containing the updated values of val1, val2, and val3 after applying the transformations.

    This function is a key part of Pollard's Rho algorithm, which uses random walks to find the factors of large numbers.

    Example:
        > new_vals(5, 3, 2, 100, 50, 6, 7)
        (35, 3, 3)

    Notes:
    - The behavior of this function is based on the Pollard's Rho algorithm, which is used for integer factorization.
    - The constants alpha and beta are used to guide the random walk through the number space.
    """
    match (val1 % 3):
        case 0:
            val1 = (val1 * val1) % N
            val2 = (val2 * 2) % n
            val3 = (val3 * 2) % n
            return val1, val2, val3
        case 1:
            val1 = (val1 * alpha) % N
            val2 = (val2 + 1) % n
            return val1, val2, val3
        case 2:
            val1 = (val1 * beta) % N
            val3 = (val3 + 1) % n
            return val1, val2, val3

def pollards_rho_alg(p: int, q: int, g: int, a: int) -> int:
    """
    Pollard's Rho algorithm to solve the discrete logarithm problem.

    This function implements Pollard's Rho algorithm to compute the discrete logarithm
    of a given value `a` with respect to the base `g` modulo a prime `p`, where the
    problem is of the form:
        g^x ≡ a (mod p)
    The algorithm is efficient for large numbers and works by exploiting
    cycle detection using random walks.

    Parameters:
    - p (int): A prime number that defines the group over which the discrete log is computed.
    - q (int): The order of the group (typically p-1 or a divisor of p-1).
    - g (int): The base for the discrete logarithm.
    - a (int): The target value in the discrete logarithm equation, i.e., the value for which g^x ≡ a (mod p).

    Returns:
    - int: The computed discrete logarithm `x`, i.e., the integer `x` such that g^x ≡ a (mod p).

    Raises:
    - ValueError: If a collision is not found within the group order or if no solution exists.

    Notes:
    - Pollard's Rho algorithm works by using a pseudo-random walk, where multiple values are
      updated based on modular arithmetic. The algorithm detects cycles in the walk and solves for
      the discrete logarithm using the differences between values.
    - The algorithm relies on the fact that if there is a collision in the values (i.e., two values
      match), it is possible to compute the discrete logarithm by solving a linear congruence.

    Example:
        > pollards_rho_alg(23, 11, 5, 17)
        7
    """
    # pollards
    n = q
    alpha = g
    beta = a
    val1 = 1
    val2 = 0
    val3 = 0
    VAL1 = val1
    VAL2 = val2
    VAL3 = val3
    for i in range(1, n):
        val1, val2, val3 = new_vals(val1, val2, val3, p, q, alpha, beta)
        VAL1, VAL2, VAL3 = new_vals(VAL1, VAL2, VAL3, p, q, alpha, beta)
        VAL1, VAL2, VAL3 = new_vals(VAL1, VAL2, VAL3, p, q, alpha, beta)
        # Check for collision
        if val1 == VAL1:
            # Solve the congruence for the discrete logarithm
            delta_a = (val2 - VAL2) % n
            delta_b = (VAL3 - val3) % n
            if delta_b == 0:
                raise ValueError("Failed to compute discrete log: no solution.")

            # Compute the discrete logarithm x
            x_return = (delta_a * pow(delta_b, -1, n)) % n
            return x_return

    raise ValueError("Failed to find collision within group order.")

if __name__ == "__main__":
    p = 103687
    q = 1571
    g = 21947
    a = 31377
    print(f"Known Values (p, q, g): {p, q, g}")
    print(f"Verification Key (a): {a}")
    message = 610
    k = 1305
    print(f"Message: {message}")
    print(f"Random Element (k): {k}")
    print("\nSolving for x via Brute Force...")
    x = brute_force_x(p, g, a)
    print(f"Solved X: {x}")
    print(f"\nComputing Signature...")
    r, s = dsa_signature(message, g, k, p, q, x)
    print(f"Signature (r, s): {r, s}")
    print(f"\nSolve via Baby Step Giant Step Algorithm...")
    x_other = baby_step_giant_step(p, g, a)
    print(f"Solved X: {x_other}")
    print(f"\nSolve via Pollards Rho Algorithm...")
    x_rho = pollards_rho_alg(p, q, g, a)
    print(f"Solved X: {x_rho}")

    print("\nLet's time the methods")
    print("Timing Brute Force Method...")
    brute_elapsed = timeit.timeit(lambda: brute_force_x(p, g, a), number=10_000)
    print(f"Time for Brute Force (10 000 runs): {brute_elapsed} Seconds")
    print(f"Average Time per solution found: {brute_elapsed/10_000} Seconds")

    print(f"\nTiming Baby Step Giant Step Method...")
    baby_step_elapsed = timeit.timeit(lambda: baby_step_giant_step(p, g, a), number=10_000)
    print(f"Time for Baby Step Giant Step Method (10 000 runs): {baby_step_elapsed} Seconds")
    print(f"Average Time per solution found: {baby_step_elapsed/10_000} Seconds")

    print(f"\nTiming Pollards Rho Algorithm...")
    pollards_elapsed = timeit.timeit(lambda: pollards_rho_alg(p, q, g, a), number=10_000)
    print(f"Time for Pollards Rho Method (10 000 runs): {pollards_elapsed} Seconds")
    print(f"Average Time per solution found: {pollards_elapsed/10_000} Seconds")
