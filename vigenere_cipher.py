"""
Vigenere Cipher Implementation with Cryptanalysis
--------------------------------------------------
CCS2243 Cryptography Essential - Individual Project (CLO3)
Project #2: Vigenere Cipher Implementation
Albukhary International University, Sem 3 2025-2026

Author: Benat Siraj Ahmed
Student ID: AIU24102456
"""

from collections import Counter


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


ENGLISH_FREQ = {
    'A': 8.17, 'B': 1.49, 'C': 2.78, 'D': 4.25, 'E': 12.70, 'F': 2.23,
    'G': 2.02, 'H': 6.09, 'I': 6.97, 'J': 0.15, 'K': 0.77, 'L': 4.03,
    'M': 2.41, 'N': 6.75, 'O': 7.51, 'P': 1.93, 'Q': 0.10, 'R': 5.99,
    'S': 6.33, 'T': 9.06, 'U': 2.76, 'V': 0.98, 'W': 2.36, 'X': 0.15,
    'Y': 1.97, 'Z': 0.07,
}


def chi_squared_score(shifted_counts: Counter, total: int) -> float:
    score = 0.0
    for letter, expected_pct in ENGLISH_FREQ.items():
        expected = expected_pct / 100.0 * total
        observed = shifted_counts.get(letter, 0)
        if expected > 0:
            score += (observed - expected) ** 2 / expected
    return score


def recover_key_letter(slice_text: str) -> str:
    best_shift, best_score = 0, float('inf')
    for shift in range(26):
        shifted = "".join(
            chr((ord(ch) - ord('A') - shift) % 26 + ord('A'))
            for ch in slice_text
        )
        score = chi_squared_score(Counter(shifted), len(slice_text))
        if score < best_score:
            best_score, best_shift = score, shift
    return chr(best_shift + ord('A'))


def recover_key(ciphertext: str, key_length: int) -> str:
    letters_only = "".join(ch for ch in ciphertext.upper() if ch.isalpha())
    slices = ["" for _ in range(key_length)]
    for i, ch in enumerate(letters_only):
        slices[i % key_length] += ch
    return "".join(recover_key_letter(s) for s in slices)


def break_vigenere(ciphertext: str, max_key_len: int = 12) -> dict:
    key_length, ic_scores = estimate_key_length(ciphertext, max_key_len)
    recovered_key = recover_key(ciphertext, key_length)
    recovered_plaintext = vigenere_decrypt(ciphertext, recovered_key)
    return {
        "ic_scores": ic_scores,
        "estimated_key_length": key_length,
        "recovered_key": recovered_key,
        "recovered_plaintext": recovered_plaintext,
    }