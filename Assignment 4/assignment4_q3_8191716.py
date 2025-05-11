####################################################################################################
#  File Name: assignment4_q3_8191716.py                                                            #
#  Description: Run DSA algorithm and demonstrate `k` reuse vulnerability                          #
#  Usage: Run from Pycharm or any other IDE, or                                                    #
#         Terminal: python assignment4_q3_8191716.py                                               #
#  Author: Philip Anderegg                                                                         #
#  Created On: 23-11-2024                                                                          #
#  Last Modified On: 26-11-2024                                                                    #
#  Student Number: 8191716                                                                         #
#  Course Name: Cryptography                                                                       #
#  Course Code: CSI 4108                                                                           #
#  Professor: Dr. Carlisle Adams                                                                   #
#  Due Date: Friday, November 29th, 2024                                                           #
####################################################################################################
import assignment4_q2_8191716 as q2

if __name__ == "__main__":
    """
    Main driver function for testing DSA signature generation, key recovery, and 
    solving for the private key (x) after reusing the per-message secret (k).

    Demonstrates vulnerability of DSA if `k` is reused.

    Steps:
    1. Generate DSA keys and parameters (p, q, g, y).
    2. Sign two different messages using the DSA signing algorithm.
    3. Use the fact that `k` was reused in both signatures (r1 == r2) to solve for `k`.
    4. Solve for the private key `x` using the DSA equation.
    5. Print the results and check if the solved values match the original ones.

    Outputs:
    - The known DSA values: p, q, g, y.
    - The two signatures: (r1, s1) and (r2, s2).
    - The value of `k` calculated from the reused signatures.
    - The private key `x` recovered from the signature equations.

    Example usage:
    - The user can call this script to see how the reuse of `k` in DSA leads to recovery 
      of private keys, and how to manipulate and work with DSA signatures.
    """
    print("Using the same implementation from Q2...")
    message1 = 582346829057612
    message2 = 8061474912583
    p, q, g = q2.dsa_global_keys()
    x, y, k = q2.dsa_keys_and_num(g, p, q)
    r1, s1 = q2.dsa_signature(message1, g, k, p, q, x)
    r2, s2 = q2.dsa_signature(message2, g, k, p, q, x)
    print(f"\nKnown Values: ")
    print(f"P: {p}")
    print(f"Q: {q}")
    print(f"G: {g}")
    print(f"Y: {y}")
    print(f"Message 1: {message1}")
    print(f"Signature 1 (r, s): {r1, s1}")
    print(f"Message 2: {message2}")
    print(f"Signature 2: {r2, s2}")
    print(f"To find x, first we solve for k, knowing it was reused.")
    print(f"A reuse of k means that r1 and r2 are equal, r1 = r2 = r\n")
    print(f"s1 = ( k_inv * ( H(M1) + x * r ) ) mod q")
    print(f"s2 = ( k_inv * ( H(M2) + x * r ) ) mod q")
    print("EQ1 minus EQ2 to eliminate x*r")
    print("s1 - s2 = k_inv * ( H(M1) - H(M2) ) mod q")
    print("k = ( H(M1) - H(M2) ) / (s1 - s2)")
    hash_m1_int = int(q2.hash_message(message1), 16)
    hash_m2_int = int(q2.hash_message(message2), 16)

    s_diff = (s1 - s2) % q
    solved_k = ((hash_m1_int - hash_m2_int) * pow(s_diff, -1, q)) % q
    print(f"Solved K: {solved_k}")
    print(f"Original K: {k}")
    print(f"Same? {k == solved_k}")
    print("\nNow Solve for the Private Key X since we have k")
    print("s2 = ( k_inv * ( H(M2) + x * r2) ) mod q")
    print("x = ( (s2 * k - H(M2)) * r_inv ) mod q")
    r2_inv = pow(r2, -1, q)
    solved_x = ( ( (s2 * k - hash_m2_int) % q ) * r2_inv ) % q
    print(f"Solved X: {solved_x}")
    print(f"Original X: {x}")
    print(f"Same? {solved_x == x}")
