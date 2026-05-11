# =============================================================
# FILE        : cipher_engine.py
# PROJECT     : CipherLab Pro — Information Security Project
# DESCRIPTION : Core cipher algorithms (XOR, Caesar, AES-256)
#               Used by both cli.py and the Flask API server.
# AUTHOR      : [Your Name]
# =============================================================

import base64
import os

# ── Try to import PyCryptodome for real AES ───────────────────
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    AES_AVAILABLE = True
except ImportError:
    AES_AVAILABLE = False


# ─────────────────────────────────────────────────────────────
# XOR CIPHER
# ─────────────────────────────────────────────────────────────

def xor_encrypt(plain_text: str, key: str) -> str:
    """
    Encrypt plain_text using XOR cipher.
    Returns hex-encoded cipher string e.g. '1B 00 2F'.
    Raises ValueError if key is empty.
    """
    if not key:
        raise ValueError("Key cannot be empty.")
    if not plain_text:
        return ""
    key_len = len(key)
    encrypted = [
        ord(ch) ^ ord(key[i % key_len])
        for i, ch in enumerate(plain_text)
    ]
    return " ".join(f"{b:02X}" for b in encrypted)


def xor_decrypt(cipher_hex: str, key: str) -> str:
    """
    Decrypt hex-encoded XOR cipher text back to plain text.
    Raises ValueError if key is empty or hex string is invalid.
    """
    if not key:
        raise ValueError("Key cannot be empty.")
    if not cipher_hex.strip():
        return ""
    try:
        byte_values = [int(h, 16) for h in cipher_hex.split()]
    except ValueError:
        raise ValueError("Invalid cipher text — expected hex pairs like '1B 2F A0'.")
    key_len = len(key)
    return "".join(
        chr(b ^ ord(key[i % key_len]))
        for i, b in enumerate(byte_values)
    )


# ─────────────────────────────────────────────────────────────
# CAESAR CIPHER
# ─────────────────────────────────────────────────────────────

def caesar_encrypt(plain_text: str, shift: int) -> str:
    """
    Encrypt using Caesar cipher with the given shift (1-25).
    Non-alphabetic characters are preserved unchanged.
    """
    shift = shift % 26
    result = []
    for ch in plain_text:
        if ch.isupper():
            result.append(chr((ord(ch) - 65 + shift) % 26 + 65))
        elif ch.islower():
            result.append(chr((ord(ch) - 97 + shift) % 26 + 97))
        else:
            result.append(ch)
    return "".join(result)


def caesar_decrypt(cipher_text: str, shift: int) -> str:
    """Decrypt Caesar cipher by reversing the shift."""
    return caesar_encrypt(cipher_text, 26 - (shift % 26))


# ─────────────────────────────────────────────────────────────
# AES-256-CBC CIPHER
# ─────────────────────────────────────────────────────────────

def _pad_key(key: str) -> bytes:
    """Pad or truncate key to exactly 32 bytes for AES-256."""
    key_bytes = key.encode("utf-8")
    return key_bytes[:32].ljust(32, b" ")


def aes_encrypt(plain_text: str, key: str) -> str:
    """
    Encrypt using AES-256-CBC.
    Returns base64-encoded string: base64(IV + ciphertext).
    Raises RuntimeError if PyCryptodome is not installed.
    """
    if not AES_AVAILABLE:
        raise RuntimeError(
            "PyCryptodome not installed. Run: pip install pycryptodome"
        )
    if not key:
        raise ValueError("Key cannot be empty.")
    iv = os.urandom(16)
    cipher = AES.new(_pad_key(key), AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plain_text.encode("utf-8"), AES.block_size))
    return base64.b64encode(iv + ct).decode("utf-8")


def aes_decrypt(cipher_b64: str, key: str) -> str:
    """
    Decrypt AES-256-CBC cipher text (base64-encoded IV+ciphertext).
    Raises ValueError on wrong key or corrupted data.
    """
    if not AES_AVAILABLE:
        raise RuntimeError(
            "PyCryptodome not installed. Run: pip install pycryptodome"
        )
    if not key:
        raise ValueError("Key cannot be empty.")
    try:
        raw = base64.b64decode(cipher_b64)
        iv, ct = raw[:16], raw[16:]
        cipher = AES.new(_pad_key(key), AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode("utf-8")
    except Exception:
        raise ValueError("Decryption failed — wrong key or corrupted cipher text.")


# ─────────────────────────────────────────────────────────────
# QUICK SELF-TEST  (run: python cipher_engine.py)
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 52)
    print("  cipher_engine.py — Self-Test")
    print("=" * 52)

    # XOR round-trip
    enc = xor_encrypt("Hello, World!", "SecretKey")
    dec = xor_decrypt(enc, "SecretKey")
    print(f"[XOR]    Plain : Hello, World!")
    print(f"[XOR]    Enc   : {enc}")
    print(f"[XOR]    Dec   : {dec}")
    print(f"[XOR]    PASS  : {dec == 'Hello, World!'}\n")

    # Caesar round-trip
    c_enc = caesar_encrypt("Hello, World!", 13)
    c_dec = caesar_decrypt(c_enc, 13)
    print(f"[Caesar] Plain : Hello, World!")
    print(f"[Caesar] Enc   : {c_enc}")
    print(f"[Caesar] Dec   : {c_dec}")
    print(f"[Caesar] PASS  : {c_dec == 'Hello, World!'}\n")

    # AES round-trip
    if AES_AVAILABLE:
        a_enc = aes_encrypt("Hello, World!", "MyStrongKey@2024")
        a_dec = aes_decrypt(a_enc, "MyStrongKey@2024")
        print(f"[AES]    Plain : Hello, World!")
        print(f"[AES]    Enc   : {a_enc[:40]}...")
        print(f"[AES]    Dec   : {a_dec}")
        print(f"[AES]    PASS  : {a_dec == 'Hello, World!'}")
    else:
        print("[AES]    SKIP  : PyCryptodome not installed.")
        print("         Run   : pip install pycryptodome")

    print("\nAll engine tests complete.")
