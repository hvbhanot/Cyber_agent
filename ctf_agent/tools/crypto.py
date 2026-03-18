from __future__ import annotations
import base64 as _b64
from ctf_agent.tools.base import BaseTool, ToolSpec, PythonExecTool


def _safe(data: str) -> str:
    """Base64-encode data so it can be safely embedded in a Python -c string."""
    return _b64.b64encode(data.encode()).decode()


def _require(data: str, tool: str, param: str) -> list[str] | None:
    """Return an error command if data is empty, else None."""
    if not data or not data.strip():
        msg = f"ERROR: {tool} requires a non-empty '{param}' argument. Pass the ciphertext/hash as {param}='...'."
        return ["python3", "-c", f"print({msg!r}); exit(1)"]
    return None


class Base64DecodeTool(PythonExecTool):
    spec = ToolSpec(
        name="base64_decode",
        description="Decode base64-encoded data",
        parameters={"data": "str"},
    )

    def build_command(self, data: str = "", **kw) -> list[str]:
        err = _require(data, "base64_decode", "data")
        if err:
            return err
        enc = _safe(data)
        code = (
            f"import base64\n"
            f"raw = base64.b64decode(base64.b64decode('{enc}').decode())\n"
            f"print(raw.decode(errors='replace'))"
        )
        return ["python3", "-c", code]


class HexDecodeTool(PythonExecTool):
    spec = ToolSpec(
        name="hex_decode",
        description="Decode hex-encoded string to ASCII",
        parameters={"data": "str"},
    )

    def build_command(self, data: str = "", **kw) -> list[str]:
        err = _require(data, "hex_decode", "data")
        if err:
            return err
        enc = _safe(data)
        code = (
            f"import binascii, base64\n"
            f"h = base64.b64decode('{enc}').decode().strip()\n"
            f"print(binascii.unhexlify(h).decode(errors='replace'))"
        )
        return ["python3", "-c", code]


class Rot13Tool(PythonExecTool):
    spec = ToolSpec(
        name="rot13",
        description="Apply ROT13 to a string (decode and encode are the same operation)",
        parameters={"data": "str"},
    )

    def build_command(self, data: str = "", **kw) -> list[str]:
        err = _require(data, "rot13", "data")
        if err:
            return err
        enc = _safe(data)
        code = (
            f"import codecs, base64\n"
            f"text = base64.b64decode('{enc}').decode()\n"
            f"print(codecs.decode(text, 'rot_13'))"
        )
        return ["python3", "-c", code]


class CryptoAnalysisTool(PythonExecTool):
    spec = ToolSpec(
        name="crypto_analysis",
        description=(
            "Classical crypto analysis. method: "
            "freq (frequency analysis), "
            "caesar (brute-force all 26 shifts), "
            "vigenere (requires key= kwarg), "
            "xor (single-byte XOR brute-force), "
            "multi (tries base64, hex, rot13, caesar automatically)"
        ),
        parameters={
            "ciphertext": "str",
            "method": "str — freq | caesar | vigenere | xor | multi | atbash | binary",
            "key": "str (optional, required for vigenere)",
        },
    )

    def build_command(self, ciphertext: str = "", method: str = "freq", key: str = "", **kw) -> list[str]:
        err = _require(ciphertext, "crypto_analysis", "ciphertext")
        if err:
            return err
        ct_enc = _safe(ciphertext)
        key_enc = _safe(key)
        code = _CRYPTO_SCRIPT.format(ct_enc=ct_enc, key_enc=key_enc, method=method)
        return ["python3", "-c", code]


_CRYPTO_SCRIPT = """\
import base64, codecs, string, collections, binascii

ct = base64.b64decode('{ct_enc}').decode(errors='replace')
key = base64.b64decode('{key_enc}').decode(errors='replace')
method = '{method}'

def freq_analysis(text):
    counts = collections.Counter(c.lower() for c in text if c.isalpha())
    total = sum(counts.values()) or 1
    ranked = sorted(counts.items(), key=lambda x: -x[1])
    print("Frequency analysis:")
    for c, n in ranked[:10]:
        print(f"  {{c}}: {{n/total:.3f}}")

def caesar_brute(text):
    print("Caesar brute-force:")
    for shift in range(26):
        dec = ''.join(
            chr((ord(c.lower()) - 97 - shift) % 26 + 97)
            if c.islower() else
            chr((ord(c.upper()) - 65 - shift) % 26 + 65)
            if c.isupper() else c
            for c in text
        )
        marker = " <-- looks like flag" if "picoctf" in dec.lower() or "flag{{" in dec.lower() else ""
        print(f"  shift={{shift:2d}}: {{dec[:80]}}{{marker}}")

def vigenere_decrypt(text, k):
    if not k:
        print("ERROR: vigenere requires key= argument")
        return
    k = k.lower()
    ki = 0
    out = []
    for c in text:
        if c.isalpha():
            shift = ord(k[ki % len(k)]) - 97
            base = 65 if c.isupper() else 97
            out.append(chr((ord(c.lower()) - 97 - shift) % 26 + base))
            ki += 1
        else:
            out.append(c)
    print("Vigenere decrypted:", ''.join(out))

def xor_brute(text):
    print("XOR single-byte brute-force:")
    raw = bytes.fromhex(text) if all(c in '0123456789abcdefABCDEF' for c in text.replace(' ','')) and len(text) > 8 else text.encode()
    found = []
    for k in range(1, 256):
        dec = bytes(b ^ k for b in raw)
        if sum(32 <= b < 127 for b in dec) / len(dec) > 0.9:
            s = dec.decode(errors='replace')
            marker = " <-- flag?" if "picoctf" in s.lower() or "flag{{" in s.lower() else ""
            found.append(f"  key=0x{{k:02x}}: {{s[:80]}}{{marker}}")
    print('\\n'.join(found[:20]) if found else "No printable results")

def atbash(text):
    out = []
    for c in text:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            out.append(chr(base + 25 - (ord(c) - base)))
        else:
            out.append(c)
    print("Atbash:", ''.join(out))

def binary_decode(text):
    chunks = text.strip().split()
    try:
        result = ''.join(chr(int(b, 2)) for b in chunks)
        print(f"Binary decoded: {{result}}")
    except Exception as e:
        print(f"Binary decode failed: {{e}}")

def multi_auto(text):
    print("=== Multi-decode attempts ===")
    # ROT13
    try:
        r = codecs.decode(text, 'rot_13')
        print(f"ROT13: {{r}}")
    except Exception as e:
        print(f"ROT13 failed: {{e}}")
    # Atbash
    try:
        out = []
        for c in text:
            if c.isalpha():
                base = 65 if c.isupper() else 97
                out.append(chr(base + 25 - (ord(c) - base)))
            else:
                out.append(c)
        print(f"Atbash: {{''.join(out)}}")
    except Exception as e:
        print(f"Atbash failed: {{e}}")
    # Base64
    try:
        r = base64.b64decode(text + '==').decode(errors='replace')
        print(f"Base64: {{r}}")
    except Exception as e:
        print(f"Base64 failed: {{e}}")
    # Hex
    try:
        r = binascii.unhexlify(text.strip()).decode(errors='replace')
        print(f"Hex: {{r}}")
    except Exception as e:
        print(f"Hex failed: {{e}}")
    # Caesar best guess (look for flag pattern)
    for shift in range(26):
        dec = ''.join(
            chr((ord(c.lower()) - 97 - shift) % 26 + 97)
            if c.islower() else
            chr((ord(c.upper()) - 65 - shift) % 26 + 65)
            if c.isupper() else c
            for c in text
        )
        if "picoctf" in dec.lower() or "flag{{" in dec.lower() or "ctf{{" in dec.lower():
            print(f"Caesar shift={{shift}}: {{dec}}")
    # XOR brute
    raw = text.encode()
    for k in range(1, 256):
        dec = bytes(b ^ k for b in raw)
        s = dec.decode(errors='replace')
        if "picoctf" in s.lower() or "flag{{" in s.lower() or "ctf{{" in s.lower():
            print(f"XOR key=0x{{k:02x}}: {{s}}")

if method == 'freq':
    freq_analysis(ct)
elif method == 'caesar':
    caesar_brute(ct)
elif method == 'vigenere':
    vigenere_decrypt(ct, key)
elif method == 'xor':
    xor_brute(ct)
elif method == 'atbash':
    atbash(ct)
elif method == 'binary':
    binary_decode(ct)
elif method == 'multi':
    multi_auto(ct)
else:
    print(f'Unknown method: {{method}}. Use: freq | caesar | vigenere | xor | atbash | binary | multi')
"""


class HashIdentifyTool(PythonExecTool):
    spec = ToolSpec(
        name="hash_identify",
        description="Identify hash type by length and attempt cracking with a common wordlist",
        parameters={"hash_value": "str — must be a hex string (MD5=32, SHA1=40, SHA256=64 chars)"},
    )

    def build_command(self, hash_value: str = "", **kw) -> list[str]:
        err = _require(hash_value, "hash_identify", "hash_value")
        if err:
            return err
        enc = _safe(hash_value)
        code = (
            f"import hashlib, base64\n"
            f"h = base64.b64decode('{enc}').decode().strip()\n"
            f"hex_chars = set('0123456789abcdefABCDEF')\n"
            f"if not all(c in hex_chars for c in h):\n"
            f"    print(f'ERROR: not a valid hex hash string (got: {{h[:40]}})')\n"
            f"    exit(1)\n"
            f"length_map = {{32: 'MD5', 40: 'SHA-1', 64: 'SHA-256', 128: 'SHA-512'}}\n"
            f"htype = length_map.get(len(h), f'Unknown (len={{len(h)}})')\n"
            f"print(f'Hash: {{h}}')\n"
            f"print(f'Likely type: {{htype}}')\n"
            f"wordlist = ['admin','password','flag','root','test','ctf','secret','letmein',\n"
            f"            '1234','12345','123456','qwerty','abc123','monkey','dragon']\n"
            f"for w in wordlist:\n"
            f"    for algo in ['md5','sha1','sha256','sha512']:\n"
            f"        if hashlib.new(algo, w.encode()).hexdigest() == h.lower():\n"
            f"            print(f'CRACKED ({{algo}}): {{w}}')\n"
            f"            exit()\n"
            f"print('Not cracked with common wordlist')\n"
        )
        return ["python3", "-c", code]


CRYPTO_TOOLS = [
    Base64DecodeTool,
    HexDecodeTool,
    Rot13Tool,
    CryptoAnalysisTool,
    HashIdentifyTool,
]
