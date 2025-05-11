import random
import math
from typing import List
import time

def miller_rabin(n: int) -> bool:
    """
    Perform the Miller-Rabin primality test on a given integer 'n'.

    This function probabilistically determines if 'n' is a prime number by using
    the Miller-Rabin algorithm. It decomposes 'n - 1' into the form 2^k * q, where
    'q' is an odd integer, and checks whether 'a^q ≡ 1 (mod n)' or
    'a^(2^j * q) ≡ -1 (mod n)' for some 0 <= j < k.

    Parameters:
    - n (int): The integer to test for primality. Should be greater than 2.

    Returns:
    - bool: True if 'n' is likely prime, and False if 'n' is definitely composite.

    Notes:
    - This is a probabilistic test, meaning it can indicate that 'n' is prime with a certain
      confidence level but cannot guarantee primality.
    - To improve confidence in the primality result, the function can be run multiple times
      with different random bases.
    """
    compute = n-1
    k=0
    while compute % 2 == 0:
        compute //= 2
        k+=1
    # At end compute = q
    a = random.randint(2, n-2)
    if pow(a, compute, n) == 1:
        return True
    for j in range(k):
        exponent = 2**j * compute
        if pow(a, exponent, n) == (n-1):
            return True
    return False
def generate_odd_int(bits: int) -> int:
    """
    Generate a random odd integer with a specified bit length.

    This function generates a random integer with the given number of bits and ensures
    that the integer is odd. The integer will be in the range [2^(bits-1), 2^bits - 1],
    making it a positive number with the specified bit length.

    Parameters:
    - bits (int): The number of bits for the generated integer. Must be greater than 1.

    Returns:
    - int: A random odd integer with the specified bit length.
    """
    rand_int = random.randint(2**(bits-1), 2**bits - 1)
    while rand_int % 2 == 0:
        rand_int = random.randint(2 ** (bits - 1), (2 ** bits) - 1)
    return rand_int

def run_n_times(n: int, number: int) -> List[bool]:
    """
    Run the Miller-Rabin primality test multiple times on a given integer.

    This function performs the Miller-Rabin primality test `n` times on the integer `number`.
    It returns a list of boolean values, where each value indicates whether the test
    considered the number to be likely prime (True) or composite (False) for a given test.

    Parameters:
    - n (int): The number of times to run the primality test.
    - number (int): The integer to test for primality.

    Returns:
    - List[bool]: A list containing the results of the Miller-Rabin test for each iteration.
                  Each entry is True if the number is probably prime for that test,
                  and False if it is composite.
    """
    out = []
    for i in range(n):
        out.append(miller_rabin(number))
    return out

def is_prime(n: int) -> bool:
    """
    Check if a given integer is prime.

    This function checks whether the integer `n` is a prime number. It first eliminates
    even numbers greater than 2, then checks divisibility by odd numbers up to the square
    root of `n`. If no divisors are found, the function returns True, indicating that the number is prime.

    Parameters:
    - n (int): The integer to check for primality. Must be greater than 1.

    Returns:
    - bool: True if `n` is prime, and False if `n` is composite.

    Example:
    - is_prime(11) returns True, because 11 is a prime number.
    - is_prime(15) returns False, because 15 is divisible by 3 and 5.
    """
    if n % 2 == 0:
        return False
    for i in range(3, math.ceil(math.sqrt(n)), 2):
        if n % i == 0:
            return False
    return True

def is_prime_opt(n: int) -> bool:
    if n <= 1:
        return False
    elif n == 2 or n == 3:
        return True

    # Check 6k+/-1
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i+2) == 0:
            return False
        i += 6

    return True

if __name__ == "__main__":
    print("Generate Odd 14-bit Integer: ")
    rand_int = generate_odd_int(14)
    print(f"{rand_int}")
    print("Running Miller-Rabin 7 times: ")
    output = run_n_times(7, rand_int)
    print(output)
    if False in output:
        print(f"Number {rand_int} is Composite (any False means not prime)")
    else:
        print(f"Number {rand_int} is probably Prime (confidence t=7)")
    print("Using is_prime function for verification: ")
    print(f"Number {rand_int} is {'not ' if not is_prime(rand_int) else ''}prime.")
    print("\nRunning until we find a prime via Miller-Rabin")
    count = 0
    while False in output:
        rand_int = generate_odd_int(14)
        output = run_n_times(7, rand_int)
        count += 1
    print(f"Number {rand_int} is probably Prime")
    print(f"Found after {count} iterations")

    time_start = time.perf_counter()
    is_prime(rand_int)
    time_end = time.perf_counter()
    print(f"\nis_prime(n) Time: {time_end - time_start} ms")
    is_prime_opt(rand_int)
    print(f"is_prime_opt(n) Time: {time.perf_counter() - time_end} ms")




