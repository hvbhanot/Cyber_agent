# Crypto Playbook

## Cipher Identification Heuristics

Before attempting decryption, identify the cipher family:

### Encoding Detection

**Base64**: Characters from `A-Za-z0-9+/`, length divisible by 4 (with `=` padding).
Can be nested — decode and check if the output is hex or another base64 string.

**Hex**: Characters from `0-9a-fA-F`, even length. Decode with `binascii.unhexlify()`.
If the result is readable ASCII, you're done. If it looks like base64, decode again.

**Binary**: Space-separated groups of 8 bits. Convert each group with `chr(int(chunk, 2))`.

**URL encoding**: `%XX` sequences. Decode with `urllib.parse.unquote()`.

### Classical Cipher Detection

**Caesar / ROT-N**: Letters only, preserves case and non-alpha chars. The "shape" of the
plaintext is visible (word lengths, punctuation). Brute-force all 26 shifts.

**ROT13**: Special case of Caesar with shift=13. Self-inverse. Very common in CTFs.

**Atbash**: Letter substitution where A↔Z, B↔Y, C↔X. Preserves case and non-alpha.
Self-inverse (applying Atbash twice returns the original). Test: if applying Atbash to
the prefix gives "pico" or "flag", you've found it.

**Vigenère**: Polyalphabetic substitution. If you have the key, decrypt character by character.
If key is unknown: Kasiski examination (find repeated sequences, GCD of distances = key length),
then frequency analysis on each key-position group.

**XOR**: If the ciphertext is hex and the description mentions "unknown key":
- Single-byte XOR: brute-force 256 keys, look for printable ASCII output with flag pattern
- Multi-byte XOR: if key length is known, split ciphertext into key-length groups and
  brute-force each position independently
- Known plaintext: if you know part of the plaintext (e.g., "picoCTF{"), XOR it with the
  corresponding ciphertext bytes to recover the key

**Substitution cipher (monoalphabetic)**: Each letter maps to a fixed different letter.
Use frequency analysis: E, T, A, O, I, N are most common in English.
If the flag format is known, the flag prefix gives you several letter mappings for free.

### Multi-Layer Encoding

Many CTF challenges chain encodings. The description usually tells you the order.
**Reverse the chain**: if the flag was "first hex-encoded, then base64-encoded",
you first base64-decode, then hex-decode.

Common chains:
- base64 → hex → ASCII
- ASCII → hex → base64
- plaintext → ROT13 → base64
- plaintext → base64 → ROT13 (ROT13 on base64 chars)

## Brute-Force Strategies

### Caesar Brute-Force (All 26 Shifts)

```python
def caesar_brute(ct, flag_prefix="picoctf"):
    for shift in range(26):
        pt = ''.join(
            chr((ord(c.lower()) - 97 - shift) % 26 + (65 if c.isupper() else 97))
            if c.isalpha() else c
            for c in ct
        )
        if flag_prefix in pt.lower():
            return shift, pt
    return None, None
```

### Double/Chained ROT

If the challenge says "ROT13 then ROT8", the total shift is 13+8=21.
Reverse: shift by 26-21=5 (or equivalently shift by -21 mod 26 = 5).

More generally, for ROT-A then ROT-B: total shift = (A+B) mod 26.
Reverse shift = 26 - ((A+B) mod 26).

### XOR Single-Byte Brute-Force

```python
import binascii

def xor_brute(hex_ct, flag_prefix=b"picoCTF"):
    raw = binascii.unhexlify(hex_ct.replace(" ", ""))
    for key in range(256):
        dec = bytes(b ^ key for b in raw)
        if flag_prefix.lower() in dec.lower():
            return key, dec.decode(errors='replace')
    # Fallback: look for high printable ratio
    best_key, best_score, best_dec = 0, 0, b""
    for key in range(256):
        dec = bytes(b ^ key for b in raw)
        score = sum(32 <= b < 127 for b in dec)
        if score > best_score:
            best_key, best_score, best_dec = key, score, dec
    return best_key, best_dec.decode(errors='replace')
```

### Vigenère with Known Key Length

```python
def vigenere_decrypt(ct, key):
    key = key.lower()
    result, ki = [], 0
    for c in ct:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - 97
            base = 65 if c.isupper() else 97
            result.append(chr((ord(c) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)
```

## Modern Crypto Pitfalls (for harder challenges)

### RSA

- Small public exponent (e=3): if plaintext^e < N, just take the e-th root
- Common modulus attack: same N, different e values → recover plaintext
- Wiener's attack: small private exponent d
- Fermat factoring: if p and q are close, N ≈ p² → factor quickly
- Hastad's broadcast attack: same message encrypted with e different public keys

### AES

- ECB mode: identical plaintext blocks → identical ciphertext blocks. Cut-and-paste attacks.
- CBC bit-flipping: modify ciphertext byte to flip corresponding plaintext bit in next block
- Padding oracle: if server reveals padding errors, decrypt one byte at a time

### Hash Cracking

- Identify hash type by length: MD5=32, SHA1=40, SHA256=64, SHA512=128 hex chars
- Try common wordlists first (rockyou, common passwords)
- Online rainbow tables: crackstation.net, hashes.com
- Hashcat modes: `-m 0` (MD5), `-m 100` (SHA1), `-m 1400` (SHA256)

## Anti-Hallucination Rules for Crypto

1. Never "guess" a flag based on the challenge name — derive it from computation
2. If your decoding produces garbage, say so — don't pretend it's readable
3. Always show the intermediate steps so the chain can be verified
4. If multiple shifts produce readable text, report all candidates — let the user decide
5. Double-check: re-encode your answer and verify it matches the original ciphertext
