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