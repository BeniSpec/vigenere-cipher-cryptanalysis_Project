# ============================================================================
# Vigenere Cipher: Full Experiment Script (Colab/Jupyter-ready)
# CCS2243 Cryptography Essential - Individual Project
# Benat Siraj Ahmed | AIU24102456
#
# Run this top to bottom (Runtime > Run all in Colab, or Run All in Jupyter).
# It regenerates every number, table, and chart used in the report --
# nothing in the report was invented; this script IS the source of truth.
# No installs needed: only uses matplotlib, which Colab/Jupyter ship with.
# ============================================================================

import time
import random
import json
from collections import Counter
import matplotlib.pyplot as plt

# ----------------------------------------------------------------------------
# PART 1: CORE CIPHER (encryption / decryption)
# ----------------------------------------------------------------------------

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


# ----------------------------------------------------------------------------
# PART 2: CRYPTANALYSIS (recovering an unknown key from ciphertext alone)
# ----------------------------------------------------------------------------

ENGLISH_FREQ = {
    'A': 8.17, 'B': 1.49, 'C': 2.78, 'D': 4.25, 'E': 12.70, 'F': 2.23,
    'G': 2.02, 'H': 6.09, 'I': 6.97, 'J': 0.15, 'K': 0.77, 'L': 4.03,
    'M': 2.41, 'N': 6.75, 'O': 7.51, 'P': 1.93, 'Q': 0.10, 'R': 5.99,
    'S': 6.33, 'T': 9.06, 'U': 2.76, 'V': 0.98, 'W': 2.36, 'X': 0.15,
    'Y': 1.97, 'Z': 0.07,
}


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


print("=" * 70)
print("PART 1 & 2 LOADED: core cipher + cryptanalysis functions ready")
print("=" * 70)

# ----------------------------------------------------------------------------
# PART 3: SANITY CHECK - known textbook vector (Kahn, 1996)
# ----------------------------------------------------------------------------
print("\n--- Textbook vector check ---")
ct = vigenere_encrypt("ATTACKATDAWN", "LEMON")
print(f"ATTACKATDAWN + LEMON -> {ct}  (expected LXFOPVEFRNHR, match={ct == 'LXFOPVEFRNHR'})")

# ----------------------------------------------------------------------------
# PART 4: MAIN CORPUS + ROUND-TRIP TEST
# ----------------------------------------------------------------------------
CORPUS = """THE QUARTERLY FINANCIAL REPORT INDICATES A SIGNIFICANT INCREASE IN
REVENUE ACROSS ALL REGIONAL DIVISIONS DURING THE LAST FISCAL PERIOD THE
MANAGEMENT TEAM HAS APPROVED THE BUDGET FOR THE UPCOMING EXPANSION INTO
NEW MARKETS INCLUDING SOUTHEAST ASIA AND EASTERN EUROPE THE SECURITY
DEPARTMENT HAS ALSO CONFIRMED THAT ALL INTERNAL SYSTEMS PASSED THE
LATEST COMPLIANCE AUDIT WITHOUT ANY MAJOR FINDINGS OR VULNERABILITIES THE
CUSTOMER SUPPORT DIVISION REPORTED A NOTABLE IMPROVEMENT IN RESPONSE TIMES
FOLLOWING THE RECENT STAFF TRAINING PROGRAM AND THE LOGISTICS TEAM
SUCCESSFULLY REDUCED AVERAGE DELIVERY TIMES ACROSS ALL WAREHOUSES BY
IMPLEMENTING AN UPDATED ROUTING ALGORITHM"""
CORPUS = " ".join(CORPUS.split())
SECRET_KEY = "CIPHER"

ciphertext = vigenere_encrypt(CORPUS, SECRET_KEY)
decrypted = vigenere_decrypt(ciphertext, SECRET_KEY)

print("\n--- Main corpus round-trip test ---")
print(f"Corpus length: {len(CORPUS)} chars, "
      f"{sum(1 for c in CORPUS if c.isalpha())} letters")
print(f"Round-trip exact match: {decrypted == CORPUS}")

# ----------------------------------------------------------------------------
# PART 5: FIGURE 1 - Letter frequency, plaintext vs ciphertext
# ----------------------------------------------------------------------------
pt_letters = [c.upper() for c in CORPUS if c.isalpha()]
ct_letters = [c.upper() for c in ciphertext if c.isalpha()]
pt_counts = Counter(pt_letters)
ct_counts = Counter(ct_letters)
alphabet = [chr(i) for i in range(65, 91)]
pt_freq = [pt_counts.get(l, 0) for l in alphabet]
ct_freq = [ct_counts.get(l, 0) for l in alphabet]

print(f"\nPlaintext IC: {index_of_coincidence(''.join(pt_letters)):.4f}  (expected ~0.067 for English)")
print(f"Ciphertext IC: {index_of_coincidence(''.join(ct_letters)):.4f}  (flattened by the 6-letter key)")

plt.figure(figsize=(9, 4.2))
plt.plot(alphabet, pt_freq, color="#1f77b4", linewidth=2, marker="o", markersize=4, label="Plaintext")
plt.plot(alphabet, ct_freq, color="#ff7f0e", linewidth=2, linestyle="--", marker="s", markersize=4, label="Ciphertext")
plt.xlabel("Letter (A-Z)")
plt.ylabel("Frequency")
plt.title("Letter Frequency: Plaintext vs Ciphertext")
plt.legend(frameon=False)
plt.gca().spines['top'].set_visible(False)
plt.gca().spines['right'].set_visible(False)
plt.tight_layout()
plt.savefig("figure1_letter_frequency.png", dpi=200)
plt.show()

# ----------------------------------------------------------------------------
# PART 6: FIGURE 2 - Index of Coincidence across candidate key lengths
# ----------------------------------------------------------------------------
result = break_vigenere(ciphertext, max_key_len=12)
ic_scores = result["ic_scores"]

print("\n--- Index of Coincidence by candidate key length ---")
for length, score in ic_scores.items():
    marker = "  <-- selected" if length == result["estimated_key_length"] else ""
    print(f"  Length {length:2d}: IC = {score:.4f}{marker}")
print(f"\nEstimated key length: {result['estimated_key_length']}")
print(f"Recovered key: {result['recovered_key']}  (secret key was: {SECRET_KEY})")
print(f"Key recovered correctly: {result['recovered_key'] == SECRET_KEY}")
print(f"Plaintext recovered exactly: "
      f"{result['recovered_plaintext'].upper().replace(' ', '') == CORPUS.upper().replace(' ', '')}")

lengths = list(ic_scores.keys())
scores = list(ic_scores.values())
colors = ["#2ca02c" if l == result["estimated_key_length"] else "#1f77b4" for l in lengths]

plt.figure(figsize=(9, 4.2))
plt.bar(lengths, scores, color=colors, edgecolor="black", linewidth=0.8)
plt.axhline(y=0.067, color="black", linestyle=":", linewidth=1.2, label="Expected English IC (~0.067)")
plt.axhline(y=0.038, color="gray", linestyle=":", linewidth=1.2, label="Expected random IC (~0.038)")
plt.xlabel("Candidate Key Length")
plt.ylabel("Average Index of Coincidence")
plt.title("Index of Coincidence by Candidate Key Length")
plt.legend(frameon=False, fontsize=8)
plt.gca().spines['top'].set_visible(False)
plt.gca().spines['right'].set_visible(False)
plt.tight_layout()
plt.savefig("figure2_ic_scores.png", dpi=200)
plt.show()

# ----------------------------------------------------------------------------
# PART 7: FIGURE 3 - Cryptanalysis accuracy vs ciphertext length
# ----------------------------------------------------------------------------
print("\n--- Accuracy vs ciphertext length experiment ---")
lengths_to_test = [30, 60, 90, 120, 180, 240, 320, 420, 579]
accuracy_results = []

for target_letters in lengths_to_test:
    count, cutoff = 0, len(CORPUS)
    for i, ch in enumerate(CORPUS):
        if ch.isalpha():
            count += 1
        if count >= target_letters:
            cutoff = i + 1
            break
    snippet = CORPUS[:cutoff]
    ct_snip = vigenere_encrypt(snippet, SECRET_KEY)
    r = break_vigenere(ct_snip, 12)
    key_correct = r["recovered_key"] == SECRET_KEY
    accuracy_results.append({
        "letters": target_letters,
        "estimated_length": r["estimated_key_length"],
        "recovered_key": r["recovered_key"],
        "key_correct": key_correct,
    })
    print(f"  {target_letters:4d} letters -> est. length {r['estimated_key_length']}, "
          f"key '{r['recovered_key']}', correct={key_correct}")

lengths2 = [r["letters"] for r in accuracy_results]
key_correct_flags = [1 if r["key_correct"] else 0 for r in accuracy_results]

plt.figure(figsize=(9, 4.2))
plt.plot(lengths2, key_correct_flags, color="#1f77b4", linewidth=2.2, marker="o", markersize=7)
plt.fill_between(lengths2, key_correct_flags, color="#1f77b4", alpha=0.15)
plt.axvline(x=240, color="#ff7f0e", linestyle="--", linewidth=1.5)
plt.text(245, 0.5, "Reliable\nfrom ~240\nletters", fontsize=8, color="#ff7f0e")
plt.xlabel("Ciphertext Length (letters)")
plt.ylabel("Key Recovered Correctly (1=Yes, 0=No)")
plt.title("Cryptanalysis Accuracy vs Ciphertext Length")
plt.yticks([0, 1])
plt.ylim(-0.15, 1.15)
plt.gca().spines['top'].set_visible(False)
plt.gca().spines['right'].set_visible(False)
plt.tight_layout()
plt.savefig("figure3_accuracy_vs_length.png", dpi=200)
plt.show()

# ----------------------------------------------------------------------------
# PART 8: FIGURE 4 - Performance benchmark
# ----------------------------------------------------------------------------
print("\n--- Performance benchmark ---")
random.seed(42)

def random_english_like(n):
    words = ["THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL", "CAN", "HER",
             "WAS", "ONE", "OUR", "OUT", "DAY", "GET", "HAS", "HIM", "HIS", "HOW",
             "MAN", "NEW", "NOW", "OLD", "SEE", "TWO", "WAY", "WHO", "DATA", "REPORT",
             "SYSTEM", "SECURE", "NETWORK", "ANALYSIS", "PROCESS", "MANAGE", "BUDGET", "REGION"]
    text, length = [], 0
    while length < n:
        w = random.choice(words)
        text.append(w)
        length += len(w) + 1
    return " ".join(text)[:n]

sizes = [500, 1000, 5000, 10000, 50000]
timing_results = []

for size in sizes:
    plaintext = random_english_like(size)
    t0 = time.perf_counter()
    ct_bench = vigenere_encrypt(plaintext, SECRET_KEY)
    t1 = time.perf_counter()
    dec_bench = vigenere_decrypt(ct_bench, SECRET_KEY)
    t2 = time.perf_counter()
    r_bench = break_vigenere(ct_bench, 12)
    t3 = time.perf_counter()

    timing_results.append({
        "size_chars": size,
        "encrypt_ms": round((t1 - t0) * 1000, 3),
        "decrypt_ms": round((t2 - t1) * 1000, 3),
        "break_ms": round((t3 - t2) * 1000, 3),
        "correct_roundtrip": dec_bench == plaintext,
        "attack_recovered_key": r_bench["recovered_key"] == SECRET_KEY,
    })
    print(f"  {size:6d} chars -> encrypt {timing_results[-1]['encrypt_ms']:8.3f} ms | "
          f"decrypt {timing_results[-1]['decrypt_ms']:8.3f} ms | "
          f"break {timing_results[-1]['break_ms']:8.3f} ms")

sizes_x = [r["size_chars"] for r in timing_results]
enc_times = [r["encrypt_ms"] for r in timing_results]
dec_times = [r["decrypt_ms"] for r in timing_results]
brk_times = [r["break_ms"] for r in timing_results]

plt.figure(figsize=(9, 4.2))
plt.plot(sizes_x, enc_times, color="#1f77b4", marker="o", label="Encrypt", linewidth=2.2)
plt.plot(sizes_x, dec_times, color="#2ca02c", marker="s", label="Decrypt", linewidth=2.2, linestyle="--")
plt.plot(sizes_x, brk_times, color="#ff7f0e", marker="^", label="Break (cryptanalysis)", linewidth=2.2, linestyle=":")
plt.xlabel("Input size (characters)")
plt.ylabel("Time (ms)")
plt.title("Performance Benchmark by Operation and Input Size")
plt.xscale("log")
plt.yscale("log")
plt.legend(frameon=False)
plt.gca().spines['top'].set_visible(False)
plt.gca().spines['right'].set_visible(False)
plt.tight_layout()
plt.savefig("figure4_timing_benchmark.png", dpi=200)
plt.show()

# ----------------------------------------------------------------------------
# PART 9: EDGE CASE / NEGATIVE TESTS
# ----------------------------------------------------------------------------
print("\n--- Edge case and negative tests ---")

# Invalid key
try:
    vigenere_encrypt("TEST", "123")
    print("  Invalid key (digits only): FAILED (should have raised ValueError)")
except ValueError:
    print("  Invalid key (digits only): PASS (ValueError raised as expected)")

# Wrong key, one letter off
pt5 = "THIS IS A CONFIDENTIAL MESSAGE ABOUT THE QUARTERLY BUDGET REVIEW"
ct5 = vigenere_encrypt(pt5, "CIPHER")
wrong_decrypt = vigenere_decrypt(ct5, "CIPHED")
diffs = sum(1 for a, b in zip(pt5.upper(), wrong_decrypt.upper()) if a != b)
pct_diff = round(100 * diffs / len(pt5), 1)
print(f"  Wrong key (CIPHED vs CIPHER): {pct_diff}% of characters differ from original")

# Very short ciphertext
short_pt = "HELLO WORLD"
short_ct = vigenere_encrypt(short_pt, "KEY")
short_result = break_vigenere(short_ct, 12)
print(f"  Very short ciphertext (11 letters): recovered key = "
      f"'{short_result['recovered_key']}' (true key was 'KEY', "
      f"correct={short_result['recovered_key'] == 'KEY'}) -- demonstrates a real limitation")

print("\n" + "=" * 70)
print("ALL EXPERIMENTS COMPLETE. Figures saved as figure1..4_*.png")
print("Compare these numbers against the report -- they should match exactly.")
print("=" * 70)
