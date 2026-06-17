#!/usr/bin/env python3
"""
CTF Crypto Toolkit — Fèmi KPONOU
Outils fréquemment utilisés en compétitions CTF
"""

from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime
import math


def rsa_small_e_attack(e, n, c):
    """Attaque RSA quand e est petit (e=3) et m^e < n."""
    m_cube = c
    # Recherche racine cubique entière
    m = int(round(m_cube ** (1/e)))
    for delta in range(-10, 10):
        candidate = m + delta
        if pow(candidate, e, n) == c:
            return long_to_bytes(candidate)
    return None


def extended_gcd(a, b):
    """Algorithme dEuclide étendu."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    return gcd, y1 - (b // a) * x1, x1


def modinv(a, m):
    """Inverse modulaire de a mod m."""
    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        raise ValueError(f"Pas dinverse : gcd({a}, {m}) = {gcd}")
    return x % m


def crt(remainders, moduli):
    """Théorème Chinois des Restes."""
    M = math.prod(moduli)
    x = 0
    for r, m in zip(remainders, moduli):
        Mi = M // m
        x += r * Mi * modinv(Mi, m)
    return x % M


def frequency_analysis(ciphertext):
    """Analyse fréquentielle pour chiffres classiques."""
    freq = {}
    for c in ciphertext.upper():
        if c.isalpha():
            freq[c] = freq.get(c, 0) + 1
    total = sum(freq.values())
    return {k: v/total for k, v in sorted(freq.items(),
                                           key=lambda x: x[1], reverse=True)}


def xor_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Déchiffrement XOR avec clé répétée."""
    return bytes(ciphertext[i] ^ key[i % len(key)]
                 for i in range(len(ciphertext)))


def find_xor_key_length(ciphertext: bytes, max_key_len: int = 40) -> list:
    """Trouve la longueur probable de clé XOR via distance de Hamming."""
    def hamming(a, b):
        return bin(int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).count("1")

    scores = []
    for key_len in range(2, min(max_key_len, len(ciphertext) // 4)):
        blocks = [ciphertext[i:i+key_len] for i in range(0, 4*key_len, key_len)]
        pairs = [(blocks[i], blocks[j])
                 for i in range(len(blocks)) for j in range(i+1, len(blocks))]
        avg_dist = sum(hamming(a, b) for a, b in pairs) / len(pairs) / key_len
        scores.append((key_len, avg_dist))

    return sorted(scores, key=lambda x: x[1])[:5]


if __name__ == "__main__":
    # Demo CRT
    print("=== CRT Demo ===")
    x = crt([2, 3, 2], [3, 5, 7])
    print(f"x = {x} (mod 105)")  # Expected: 23

    # Demo modinv
    print("\n=== RSA Key Demo ===")
    e, p, q = 65537, 61, 53
    n = p * q
    phi = (p-1) * (q-1)
    d = modinv(e, phi)
    print(f"n={n}, e={e}, d={d}")
    m = 42
    c = pow(m, e, n)
    print(f"Chiffré: {c}")
    print(f"Déchiffré: {pow(c, d, n)}")
