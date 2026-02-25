#!/usr/bin/env python3
"""
Calculate secrets needed for 75% chance of ANY collision between two distinct secrets
This is the classic birthday paradox problem for 11-bit hash (2048 possible values)
"""

import math

def main():
    # Hash produces 11-bit output
    hash_bits = 11
    
    # We want 75% chance of ANY collision between two secrets
    target_prob = 0.75
    
    # Total possible hash values = 2^11 = 2048
    N = 2 ** hash_bits
    
    # Birthday paradox formula: n ≈ √(2 * N * ln(1/(1-P)))
    # Where P is probability of collision, N is size of hash space
    n_secrets = math.sqrt(2 * N * math.log(1 / (1 - target_prob)))
    
    # Round up to nearest integer
    result = math.ceil(n_secrets)
    
    # Display the answer
    print(f"Secrets needed for 75% chance of ANY collision: {result}")

if __name__ == "__main__":
    main()
