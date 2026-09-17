"""
Vigenere Cipher Implementation with Cryptanalysis
--------------------------------------------------
CCS2243 Cryptography Essential - Individual Project (CLO3)
Project #2: Vigenere Cipher Implementation
Albukhary International University, Sem 3 2025-2026

Author: Benat Siraj Ahmed
Student ID: AIU24102456
"""


def clean_key(key: str) -> str:
    return "".join(ch for ch in key if ch.isalpha()).upper()


def vigenere_encrypt(plaintext: str, key: str) -> str:
    key = clean_key(key)
    if not key:
        raise ValueError("Key must contain at least one alphabetic character.")
    result, key_index, key_len = [], 0, len(key)
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            p = ord(char.upper()) - ord('A')
            k = ord(key[key_index % key_len]) - ord('A')
            result.append(chr((p + k) % 26 + base))
            key_index += 1
        else:
            result.append(char)
    return "".join(result)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    key = clean_key(key)
    if not key:
        raise ValueError("Key must contain at least one alphabetic character.")
    result, key_index, key_len = [], 0, len(key)
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            c = ord(char.upper()) - ord('A')
            k = ord(key[key_index % key_len]) - ord('A')
            result.append(chr((c - k) % 26 + base))
            key_index += 1
        else:
            result.append(char)
    return "".join(result)


def index_of_coincidence(text: str) -> float:
    freqs = Counter(text)
    n = len(text)
    if n < 2:
        return 0.0
    numerator = sum(f * (f - 1) for f in freqs.values())
    return numerator / (n * (n - 1))


def estimate_key_length(ciphertext: str, max_len: int = 12):
    letters_only = "".join(ch for ch in ciphertext.upper() if ch.isalpha())
    scores = {}
    for candidate_len in range(1, max_len + 1):
        slices = ["" for _ in range(candidate_len)]
        for i, ch in enumerate(letters_only):
            slices[i % candidate_len] += ch
        avg_ic = sum(index_of_coincidence(s) for s in slices) / candidate_len
        scores[candidate_len] = avg_ic
    threshold = 0.058
    above = [l for l, s in scores.items() if s >= threshold]
    best_len = min(above) if above else max(scores, key=scores.get)
    return best_len, scores