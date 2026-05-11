# =============================================================
# FILE        : cli.py
# PROJECT     : CipherLab Pro — Information Security Project
# DESCRIPTION : Interactive console interface.
#               Run: python cli.py
# AUTHOR      : [Your Name]
# =============================================================

import sys
import os

# Import cipher functions from cipher_engine.py (same directory)
try:
    from cipher_engine import (
        xor_encrypt, xor_decrypt,
        caesar_encrypt, caesar_decrypt,
        aes_encrypt, aes_decrypt,
        AES_AVAILABLE,
    )
except ImportError:
    print("[ERROR] cipher_engine.py not found in the same folder.")
    print("        Make sure cipher_engine.py is in the same directory as cli.py")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

WIDTH = 58

def banner():
    print("=" * WIDTH)
    print("   CIPHERLAB PRO — Text Encryption & Decryption Tool")
    print("   Information Security | BS Software Engineering")
    print("=" * WIDTH)
    print(f"   Algorithms : XOR  |  Caesar  |  AES-256")
    print(f"   AES Status : {'Available (PyCryptodome)' if AES_AVAILABLE else 'Not available — pip install pycryptodome'}")
    print("=" * WIDTH)

def section(title):
    print(f"\n  {'─'*4} {title} {'─'*(WIDTH - len(title) - 8)}")

def prompt(msg):
    return input(f"  {msg}: ").strip()

def info(msg):
    print(f"  ✓ {msg}")

def error(msg):
    print(f"  ✗ {msg}")


# ─────────────────────────────────────────────────────────────
# MODE MENUS
# ─────────────────────────────────────────────────────────────

def run_xor():
    section("XOR CIPHER")
    plain_text = ""
    key        = ""
    encrypted  = ""

    while True:
        print()
        print("    1. Enter / Update Text")
        print("    2. Set / Update Key")
        print("    3. Encrypt")
        print("    4. Decrypt")
        print("    5. Show State")
        print("    0. Back to Main Menu")
        choice = prompt("Choice")

        if choice == "1":
            plain_text = prompt("Enter text")
            encrypted  = ""
            info(f"Text saved ({len(plain_text)} chars).")

        elif choice == "2":
            key = prompt("Enter key")
            encrypted = ""
            info(f"Key saved ({len(key)} chars).")

        elif choice == "3":
            if not plain_text:
                error("Enter text first (option 1).")
            elif not key:
                error("Enter a key first (option 2).")
            else:
                try:
                    encrypted = xor_encrypt(plain_text, key)
                    print(f"\n  Original  : {plain_text}")
                    print(f"  Encrypted : {encrypted}")
                    info("XOR encryption successful.")
                except ValueError as e:
                    error(str(e))

        elif choice == "4":
            if not encrypted:
                error("Encrypt something first (option 3).")
            elif not key:
                error("Enter a key first (option 2).")
            else:
                try:
                    decrypted = xor_decrypt(encrypted, key)
                    print(f"\n  Encrypted : {encrypted}")
                    print(f"  Decrypted : {decrypted}")
                    match = "✓ MATCH" if decrypted == plain_text else "✗ MISMATCH"
                    info(f"Verification : {match}")
                except ValueError as e:
                    error(str(e))

        elif choice == "5":
            masked = (key[:2] + "*" * (len(key)-2)) if len(key) > 2 else "***"
            print(f"\n  Text      : {plain_text or '(not set)'}")
            print(f"  Key       : {masked if key else '(not set)'}")
            print(f"  Encrypted : {encrypted or '(not encrypted)'}")

        elif choice == "0":
            break
        else:
            error("Invalid choice.")


def run_caesar():
    section("CAESAR CIPHER")
    plain_text = ""
    shift      = 3
    encrypted  = ""

    while True:
        print()
        print(f"    Current shift: {shift}  (A → {chr((65 + shift) % 26 + 65)})")
        print("    1. Enter / Update Text")
        print("    2. Set Shift Value (1-25)")
        print("    3. Encrypt")
        print("    4. Decrypt")
        print("    0. Back to Main Menu")
        choice = prompt("Choice")

        if choice == "1":
            plain_text = prompt("Enter text")
            encrypted  = ""
            info(f"Text saved ({len(plain_text)} chars).")

        elif choice == "2":
            try:
                s = int(prompt("Enter shift (1-25)"))
                if 1 <= s <= 25:
                    shift = s
                    encrypted = ""
                    info(f"Shift set to {shift}.")
                else:
                    error("Shift must be between 1 and 25.")
            except ValueError:
                error("Please enter a number.")

        elif choice == "3":
            if not plain_text:
                error("Enter text first (option 1).")
            else:
                encrypted = caesar_encrypt(plain_text, shift)
                print(f"\n  Original  : {plain_text}")
                print(f"  Encrypted : {encrypted}")
                info(f"Caesar encryption successful (shift={shift}).")

        elif choice == "4":
            if not encrypted:
                error("Encrypt something first (option 3).")
            else:
                decrypted = caesar_decrypt(encrypted, shift)
                print(f"\n  Encrypted : {encrypted}")
                print(f"  Decrypted : {decrypted}")
                match = "✓ MATCH" if decrypted == plain_text else "✗ MISMATCH"
                info(f"Verification : {match}")

        elif choice == "0":
            break
        else:
            error("Invalid choice.")


def run_aes():
    section("AES-256-CBC CIPHER")
    if not AES_AVAILABLE:
        error("PyCryptodome is not installed.")
        print("  Run:  pip install pycryptodome")
        print("  Then restart this program.")
        return

    plain_text = ""
    key        = ""
    encrypted  = ""

    while True:
        print()
        print("    1. Enter / Update Text")
        print("    2. Set / Update Key")
        print("    3. Encrypt")
        print("    4. Decrypt")
        print("    0. Back to Main Menu")
        choice = prompt("Choice")

        if choice == "1":
            plain_text = prompt("Enter text")
            encrypted  = ""
            info(f"Text saved ({len(plain_text)} chars).")

        elif choice == "2":
            key = prompt("Enter key (any length, padded to 32 bytes)")
            encrypted = ""
            info(f"Key saved ({len(key)} chars).")

        elif choice == "3":
            if not plain_text:
                error("Enter text first (option 1).")
            elif not key:
                error("Enter a key first (option 2).")
            else:
                try:
                    encrypted = aes_encrypt(plain_text, key)
                    print(f"\n  Original  : {plain_text}")
                    print(f"  Encrypted : {encrypted[:60]}{'...' if len(encrypted)>60 else ''}")
                    info("AES-256-CBC encryption successful.")
                except Exception as e:
                    error(str(e))

        elif choice == "4":
            if not encrypted:
                error("Encrypt something first (option 3).")
            elif not key:
                error("Enter a key first (option 2).")
            else:
                try:
                    decrypted = aes_decrypt(encrypted, key)
                    print(f"\n  Encrypted : {encrypted[:50]}...")
                    print(f"  Decrypted : {decrypted}")
                    match = "✓ MATCH" if decrypted == plain_text else "✗ MISMATCH"
                    info(f"Verification : {match}")
                except ValueError as e:
                    error(str(e))

        elif choice == "0":
            break
        else:
            error("Invalid choice.")


def run_compare():
    section("COMPARE ALL ALGORITHMS")
    text = prompt("Enter text to encrypt with all algorithms")
    if not text:
        error("No text entered.")
        return

    key   = prompt("Enter key (for XOR and AES)")
    shift_raw = prompt("Enter Caesar shift (1-25, default=3)")
    try:
        shift = int(shift_raw) if shift_raw else 3
        shift = max(1, min(25, shift))
    except ValueError:
        shift = 3

    print()
    print(f"  {'─'*50}")
    print(f"  Original Text : {text}")
    print(f"  {'─'*50}")

    # XOR
    if key:
        try:
            xor_out = xor_encrypt(text, key)
            print(f"  XOR     : {xor_out[:60]}{'...' if len(xor_out)>60 else ''}")
        except ValueError as e:
            print(f"  XOR     : ERROR — {e}")
    else:
        print("  XOR     : (skipped — no key provided)")

    # Caesar
    cas_out = caesar_encrypt(text, shift)
    print(f"  Caesar  : {cas_out}  (shift={shift})")

    # AES
    if AES_AVAILABLE and key:
        try:
            aes_out = aes_encrypt(text, key)
            print(f"  AES-256 : {aes_out[:60]}...")
        except Exception as e:
            print(f"  AES-256 : ERROR — {e}")
    elif not AES_AVAILABLE:
        print("  AES-256 : (not available — pip install pycryptodome)")
    else:
        print("  AES-256 : (skipped — no key provided)")

    print(f"  {'─'*50}")


# ─────────────────────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────────────────────

def main():
    os.system("cls" if os.name == "nt" else "clear")
    banner()

    while True:
        print()
        print("  MAIN MENU")
        print("  " + "─" * 30)
        print("  1. XOR Cipher")
        print("  2. Caesar Cipher")
        print("  3. AES-256-CBC Cipher")
        print("  4. Compare All Algorithms")
        print("  0. Exit")
        print()
        choice = prompt("Select option")

        if choice == "1":
            run_xor()
        elif choice == "2":
            run_caesar()
        elif choice == "3":
            run_aes()
        elif choice == "4":
            run_compare()
        elif choice == "0":
            print()
            print("  Thank you for using CipherLab Pro. Goodbye!")
            print("=" * WIDTH)
            break
        else:
            error("Invalid choice. Enter 0-4.")


if __name__ == "__main__":
    main()
