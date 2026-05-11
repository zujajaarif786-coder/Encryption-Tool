# =============================================================
# FILE        : api_server.py
# PROJECT     : CipherLab Pro — Information Security Project
# DESCRIPTION : Flask REST API — bridges the HTML frontend
#               (index.html) with the Python cipher engine.
# RUN         : python api_server.py
#               Then open http://localhost:5000 in browser.
# AUTHOR      : [Your Name]
# =============================================================

import os
import json
from flask import Flask, request, jsonify, send_from_directory

# Import cipher engine from the same directory
try:
    from cipher_engine import (
        xor_encrypt, xor_decrypt,
        caesar_encrypt, caesar_decrypt,
        aes_encrypt, aes_decrypt,
        AES_AVAILABLE,
    )
except ImportError:
    raise SystemExit("[ERROR] cipher_engine.py not found. Place it in the same folder.")

# ── Flask setup ───────────────────────────────────────────────
app = Flask(__name__, static_folder=".")


# ─────────────────────────────────────────────────────────────
# SERVE FRONTEND
# ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the HTML frontend."""
    return send_from_directory(".", "index.html")


# ─────────────────────────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────────────────────────

def ok(data: dict):
    """Return a JSON success response."""
    return jsonify({"status": "ok", **data})

def err(message: str, code: int = 400):
    """Return a JSON error response."""
    return jsonify({"status": "error", "message": message}), code


# ─────────────────────────────────────────────────────────────
# XOR ENDPOINTS
# ─────────────────────────────────────────────────────────────

@app.route("/api/xor/encrypt", methods=["POST"])
def api_xor_encrypt():
    data = request.get_json(force=True, silent=True) or {}
    text = data.get("text", "")
    key  = data.get("key",  "")
    if not text:
        return err("'text' field is required.")
    if not key:
        return err("'key' field is required.")
    try:
        result = xor_encrypt(text, key)
        return ok({"encrypted": result, "bytes": len(result.split())})
    except ValueError as e:
        return err(str(e))


@app.route("/api/xor/decrypt", methods=["POST"])
def api_xor_decrypt():
    data = request.get_json(force=True, silent=True) or {}
    cipher = data.get("cipher", "")
    key    = data.get("key",    "")
    if not cipher:
        return err("'cipher' field is required.")
    if not key:
        return err("'key' field is required.")
    try:
        result = xor_decrypt(cipher, key)
        return ok({"decrypted": result})
    except ValueError as e:
        return err(str(e))


# ─────────────────────────────────────────────────────────────
# CAESAR ENDPOINTS
# ─────────────────────────────────────────────────────────────

@app.route("/api/caesar/encrypt", methods=["POST"])
def api_caesar_encrypt():
    data  = request.get_json(force=True, silent=True) or {}
    text  = data.get("text",  "")
    shift = data.get("shift", 3)
    if not text:
        return err("'text' field is required.")
    try:
        shift = int(shift)
    except (ValueError, TypeError):
        return err("'shift' must be an integer.")
    result = caesar_encrypt(text, shift)
    return ok({"encrypted": result, "shift": shift % 26})


@app.route("/api/caesar/decrypt", methods=["POST"])
def api_caesar_decrypt():
    data   = request.get_json(force=True, silent=True) or {}
    cipher = data.get("cipher", "")
    shift  = data.get("shift",  3)
    if not cipher:
        return err("'cipher' field is required.")
    try:
        shift = int(shift)
    except (ValueError, TypeError):
        return err("'shift' must be an integer.")
    result = caesar_decrypt(cipher, shift)
    return ok({"decrypted": result, "shift": shift % 26})


# ─────────────────────────────────────────────────────────────
# AES ENDPOINTS
# ─────────────────────────────────────────────────────────────

@app.route("/api/aes/encrypt", methods=["POST"])
def api_aes_encrypt():
    if not AES_AVAILABLE:
        return err("PyCryptodome not installed. Run: pip install pycryptodome", 503)
    data = request.get_json(force=True, silent=True) or {}
    text = data.get("text", "")
    key  = data.get("key",  "")
    if not text:
        return err("'text' field is required.")
    if not key:
        return err("'key' field is required.")
    try:
        result = aes_encrypt(text, key)
        return ok({"encrypted": result})
    except Exception as e:
        return err(str(e))


@app.route("/api/aes/decrypt", methods=["POST"])
def api_aes_decrypt():
    if not AES_AVAILABLE:
        return err("PyCryptodome not installed. Run: pip install pycryptodome", 503)
    data   = request.get_json(force=True, silent=True) or {}
    cipher = data.get("cipher", "")
    key    = data.get("key",    "")
    if not cipher:
        return err("'cipher' field is required.")
    if not key:
        return err("'key' field is required.")
    try:
        result = aes_decrypt(cipher, key)
        return ok({"decrypted": result})
    except ValueError as e:
        return err(str(e))


# ─────────────────────────────────────────────────────────────
# STATUS ENDPOINT
# ─────────────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    return ok({
        "server":        "CipherLab Pro API",
        "version":       "3.0",
        "aes_available": AES_AVAILABLE,
        "algorithms":    ["XOR", "Caesar", "AES-256-CBC"],
    })


# ─────────────────────────────────────────────────────────────
# RUN SERVER
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 52)
    print("  CipherLab Pro — API Server")
    print("=" * 52)
    print(f"  AES     : {'Available' if AES_AVAILABLE else 'Not available (pip install pycryptodome)'}")
    print(f"  URL     : http://localhost:5000")
    print(f"  Frontend: http://localhost:5000  (serves index.html)")
    print("=" * 52)
    print("  Press Ctrl+C to stop.\n")
    app.run(debug=False, port=5000)
