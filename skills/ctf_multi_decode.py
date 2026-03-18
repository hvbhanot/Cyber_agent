#!/usr/bin/env python3
"""
ctf_multi_decode.py — Quick multi-decode utility for CTF crypto challenges.
Tries all common decodings on input and reports any flag-pattern matches.

Usage:
    python3 ctf_multi_decode.py "ciphertext_here"
    echo "ciphertext" | python3 ctf_multi_decode.py
"""
import sys
import base64
import binascii
import codecs
import re

FLAG_PATTERNS = [
    re.compile(r'(?:picoCTF|flag|CTF|HTB|THM)\{[^\}]+\}', re.IGNORECASE),
]

def check_flag(text, label):
    for pat in FLAG_PATTERNS:
        matches = pat.findall(text)
        if matches:
            for m in matches:
                print(f"\n{'='*60}")
                print(f"  *** FLAG FOUND via {label}: {m}")
                print(f"{'='*60}\n")
            return True
    return False

def try_rot_n(text, n):
    return ''.join(
        chr((ord(c) - ord('a') - n) % 26 + ord('a')) if c.islower() else
        chr((ord(c) - ord('A') - n) % 26 + ord('A')) if c.isupper() else c
        for c in text
    )

def try_atbash(text):
    return ''.join(
        chr(ord('a') + 25 - (ord(c) - ord('a'))) if c.islower() else
        chr(ord('A') + 25 - (ord(c) - ord('A'))) if c.isupper() else c
        for c in text
    )

def try_base64(text):
    try:
        padded = text.strip() + '=' * (-len(text.strip()) % 4)
        return base64.b64decode(padded).decode(errors='replace')
    except Exception:
        return None

def try_hex(text):
    try:
        cleaned = text.strip().replace(' ', '').replace('0x', '')
        return binascii.unhexlify(cleaned).decode(errors='replace')
    except Exception:
        return None

def try_xor_brute(text):
    """XOR brute force on hex input."""
    try:
        cleaned = text.strip().replace(' ', '')
        raw = bytes.fromhex(cleaned)
    except Exception:
        return []

    results = []
    for key in range(1, 256):
        dec = bytes(b ^ key for b in raw)
        if sum(32 <= b < 127 for b in dec) / max(len(dec), 1) > 0.85:
            s = dec.decode(errors='replace')
            results.append((key, s))
    return results

def try_decimal_ascii(text):
    """Space-separated decimal → ASCII."""
    try:
        nums = text.strip().split()
        return ''.join(chr(int(n)) for n in nums)
    except Exception:
        return None

def try_binary(text):
    """Space-separated binary → ASCII."""
    try:
        chunks = text.strip().split()
        if all(set(c) <= {'0', '1'} for c in chunks):
            return ''.join(chr(int(b, 2)) for b in chunks)
    except Exception:
        pass
    return None

def main():
    if len(sys.argv) > 1:
        ct = ' '.join(sys.argv[1:])
    else:
        ct = sys.stdin.read().strip()

    if not ct:
        print("Usage: python3 ctf_multi_decode.py 'ciphertext'")
        sys.exit(1)

    print(f"Input ({len(ct)} chars): {ct[:100]}{'...' if len(ct) > 100 else ''}\n")
    print("-" * 60)

    found = False

    # ROT13
    r = codecs.decode(ct, 'rot_13')
    print(f"ROT13: {r[:100]}")
    found |= check_flag(r, "ROT13")

    # Atbash
    r = try_atbash(ct)
    print(f"Atbash: {r[:100]}")
    found |= check_flag(r, "Atbash")

    # All Caesar shifts (only print hits)
    print("\nCaesar brute-force (showing flag matches only):")
    for shift in range(1, 26):
        if shift == 13:
            continue  # Already did ROT13
        dec = try_rot_n(ct, shift)
        if check_flag(dec, f"Caesar shift={shift}"):
            print(f"  shift={shift}: {dec[:100]}")
            found = True

    # Base64
    r = try_base64(ct)
    if r:
        print(f"\nBase64: {r[:100]}")
        found |= check_flag(r, "Base64")
        # Check if base64 result is hex
        hex_r = try_hex(r)
        if hex_r:
            print(f"Base64→Hex: {hex_r[:100]}")
            found |= check_flag(hex_r, "Base64→Hex")

    # Hex
    r = try_hex(ct)
    if r:
        print(f"\nHex: {r[:100]}")
        found |= check_flag(r, "Hex")
        # Check if hex result is base64
        b64_r = try_base64(r)
        if b64_r:
            print(f"Hex→Base64: {b64_r[:100]}")
            found |= check_flag(b64_r, "Hex→Base64")

    # XOR brute (only if input looks like hex)
    is_hex = all(c in '0123456789abcdefABCDEF ' for c in ct.replace('0x', ''))
    if is_hex and len(ct.replace(' ', '')) >= 8:
        xor_results = try_xor_brute(ct)
        if xor_results:
            print(f"\nXOR brute-force ({len(xor_results)} printable results):")
            for key, s in xor_results[:10]:
                print(f"  key=0x{key:02x}: {s[:80]}")
                found |= check_flag(s, f"XOR key=0x{key:02x}")

    # Decimal ASCII
    r = try_decimal_ascii(ct)
    if r:
        print(f"\nDecimal ASCII: {r[:100]}")
        found |= check_flag(r, "Decimal ASCII")

    # Binary
    r = try_binary(ct)
    if r:
        print(f"\nBinary: {r[:100]}")
        found |= check_flag(r, "Binary")

    # Chained: ROT13 then Base64
    rot_first = codecs.decode(ct, 'rot_13')
    b64_r = try_base64(rot_first)
    if b64_r:
        print(f"\nROT13→Base64: {b64_r[:100]}")
        found |= check_flag(b64_r, "ROT13→Base64")

    print("\n" + "-" * 60)
    if not found:
        print("No flag pattern found. Try:")
        print("  - Different ciphertext extraction from the challenge")
        print("  - Vigenère with a guessed key")
        print("  - Multi-byte XOR")
        print("  - Custom encoding specific to the challenge")
    else:
        print("Flag candidate(s) found above! Verify before submitting.")

if __name__ == "__main__":
    main()
