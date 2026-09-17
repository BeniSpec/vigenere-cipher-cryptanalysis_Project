# Vigenère Cipher Implementation and Cryptanalysis

CCS2243 – Cryptography Essential | Individual Project (Assessment 1, 20%)
Albukhary International University | Semester 3, 2025-2026

**Author:** Benat Siraj Ahmed (AIU24102456)

## What this is

A self-contained Python implementation of the Vigenère cipher with two modes:

1. **Encrypt/Decrypt** — standard Vigenère encryption and decryption when the key is known.
2. **Break ciphertext** — cryptanalysis that recovers an unknown key from ciphertext alone, using the Index of Coincidence (key-length estimation) and chi-squared frequency analysis (key-letter recovery).

Full write-up, design diagrams, and measured results are in the final report.

## Files

| File | Purpose |
|---|---|
| `vigenere_cipher.py` | Core implementation: encrypt, decrypt, IC-based key-length estimation, chi-squared key recovery, and the console menu. This is the file to run for the live demo. |
| `vigenere_full_experiment.py` | Generates the measured evidence in the report — round-trip tests, IC-vs-key-length table, accuracy-vs-ciphertext-length experiment, performance benchmark, and the 4 charts (Figures 5–8). |
| `Vigenere_Cipher_Report.pdf` | Final submitted report. |
| `evidence/` | Screenshots referenced in Appendix E of the report (console runs + CrypTool 2). |

## How to run

```bash
python3 vigenere_cipher.py
```

Then choose:
- `1` to encrypt
- `2` to decrypt
- `3` to break a ciphertext with no key given
- `4` to exit

To reproduce every measured result and chart in the report:

```bash
python3 vigenere_full_experiment.py
```

## Academic integrity note

This is individual coursework submitted for CCS2243 at Albukhary International University. Generative AI (Claude, Anthropic) was used for code review, verifying the IC/chi-squared math, and proofreading, as disclosed in Appendix D of the report. All code was written, run, and understood by the author.
