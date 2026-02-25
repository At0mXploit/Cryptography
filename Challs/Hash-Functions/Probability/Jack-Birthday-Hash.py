#!/usr/bin/env python3
"""
Birthday Paradox to calculate secrets needed for 50% chance of collision 
with Jack's specific 11-bit hash: 01011001101
"""

import math

def main():
    # Hash produces 11-bit output
    hash_bits = 11
    
    # We want 50% chance of collision
    target_prob = 0.5
    
    # Total possible hash values = 2^11 = 2048
    N = 2 ** hash_bits
    
    # Formula: n = ln(1 - P) / ln(1 - 1/N)
    # Where P is target probability, N is size of hash space
    n_secrets = math.log(1 - target_prob) / math.log(1 - 1/N)
    
    # Round up to nearest integer (can't have partial secrets)
    result = math.ceil(n_secrets)
    
    # Display the answer
    print(f"Secrets needed for 50% collision: {result}")

if __name__ == "__main__":
    main()
