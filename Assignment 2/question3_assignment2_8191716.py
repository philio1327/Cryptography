import sympy
import random

num1 = random.randrange(2**13, 2**14)
num2 = random.randrange(2**13, 2**14)

while num1 % 4 != 3 or not sympy.isprime(num1):
    num1 = random.randrange(2**13, 2**14)

while num2 % 4 != 3 or not sympy.isprime(num2):
    num2 = random.randrange(2**13, 2**14)

print(f"Prime p is: {num1}\nPrime q is: {num2}")

modulus = num1 * num2

print(f"Modulus is: {modulus}")

x0_seed = random.randrange(2, modulus)

while sympy.gcd(x0_seed, modulus) != 1:
    x0_seed = random.randrange(2, modulus)

print(f"Seed is: {x0_seed}")

print("Computing x_n values:")

def compute(x, mod):
    return x*x % mod

x_next = compute(x0_seed, modulus)
print(f"x_1 is {x_next}, LSB: {x_next % 2}")
for i in range(1, 15):
    x_next = compute(x_next, modulus)
    print(f"x_{i+1} is {x_next}, LSB: {x_next % 2}")


