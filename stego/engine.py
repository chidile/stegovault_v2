"""
LSB (Least Significant Bit) Steganography Engine
Hides/reveals text messages inside PNG/BMP images.
Optionally encrypts the payload with AES-256-GCM (password-based, PBKDF2).
Falls back to PBKDF2+HMAC-XOR if `cryptography` is not installed.
"""
from PIL import Image
import io
import os
import hashlib
import hmac as hmac_mod
import struct

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

DELIMITER      = "<<END>>"
PASSWORD_MAGIC = b"\xDE\xAD\xBE\xEF"
SALT_LEN       = 16
NONCE_LEN      = 12
PBKDF2_ITERS   = 200_000


# ─── Key derivation ──────────────────────────────────────────────────────────

def _derive_key(password: str, salt: bytes) -> bytes:
    if _HAS_CRYPTO:
        kdf = PBKDF2HMAC(
            algorithm=crypto_hashes.SHA256(),
            length=32, salt=salt, iterations=PBKDF2_ITERS,
        )
        return kdf.derive(password.encode("utf-8"))
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERS, dklen=32
    )


# ─── XOR stream (fallback) ───────────────────────────────────────────────────

def _xor_stream(data: bytes, key: bytes, nonce: bytes) -> bytes:
    stream, counter = b"", 0
    seed = key + nonce
    while len(stream) < len(data):
        stream += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(a ^ b for a, b in zip(data, stream[: len(data)]))


# ─── Encrypt / decrypt ───────────────────────────────────────────────────────

def _encrypt_payload(plaintext: bytes, password: str) -> bytes:
    """Return MAGIC + SALT + NONCE + ciphertext (+ HMAC tag for fallback)."""
    salt  = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key   = _derive_key(password, salt)
    if _HAS_CRYPTO:
        ct = AESGCM(key).encrypt(nonce, plaintext, None)
    else:
        ct  = _xor_stream(plaintext, key, nonce)
        ct += hmac_mod.new(key, nonce + ct, hashlib.sha256).digest()
    return PASSWORD_MAGIC + salt + nonce + ct


def _decrypt_payload(payload: bytes, password: str) -> bytes:
    if not payload.startswith(PASSWORD_MAGIC):
        raise ValueError("Payload is not encrypted or is corrupt.")
    off  = len(PASSWORD_MAGIC)
    salt = payload[off: off + SALT_LEN];  off += SALT_LEN
    nonce= payload[off: off + NONCE_LEN]; off += NONCE_LEN
    ct   = payload[off:]
    key  = _derive_key(password, salt)
    if _HAS_CRYPTO:
        try:
            return AESGCM(key).decrypt(nonce, ct, None)
        except Exception:
            raise ValueError("Wrong password or corrupted data.")
    else:
        if len(ct) < 32:
            raise ValueError("Payload too short — corrupted.")
        tag_ok = ct[-32:]
        ct     = ct[:-32]
        if not hmac_mod.compare_digest(
            hmac_mod.new(key, nonce + ct, hashlib.sha256).digest(), tag_ok
        ):
            raise ValueError("Wrong password or corrupted data.")
        return _xor_stream(ct, key, nonce)


# ─── Bit helpers ─────────────────────────────────────────────────────────────

def _to_bits(data: bytes) -> list:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _from_bits(bits: list) -> bytes:
    out = []
    for i in range(0, len(bits), 8):
        chunk = bits[i: i + 8]
        if len(chunk) < 8:
            break
        byte = 0
        for b in chunk:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)


# ─── Public API ──────────────────────────────────────────────────────────────

def encode_message(image_bytes: bytes, message: str, password: str = "") -> bytes:
    """Embed a secret message; encrypt with password if supplied."""
    img    = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    pixels = list(img.getdata())
    width, height = img.size

    raw = message.encode("utf-8") + DELIMITER.encode("utf-8")

    if password:
        enc     = _encrypt_payload(raw, password)
        payload = struct.pack(">I", len(enc)) + enc
    else:
        payload = raw

    bits     = _to_bits(payload)
    max_bits = len(pixels) * 3

    if len(bits) > max_bits:
        raise ValueError(
            f"Message too large: needs {len(bits)} bits, "
            f"image can hold {max_bits} bits (~{max_bits // 8} usable bytes)."
        )

    bit_idx    = 0
    new_pixels = []
    for r, g, b in pixels:
        new_ch = []
        for ch in (r, g, b):
            if bit_idx < len(bits):
                ch = (ch & ~1) | bits[bit_idx]
                bit_idx += 1
            new_ch.append(ch)
        new_pixels.append(tuple(new_ch))

    out = Image.new("RGB", (width, height))
    out.putdata(new_pixels)
    buf = io.BytesIO()
    out.save(buf, format="PNG")
    return buf.getvalue()


def decode_message(image_bytes: bytes, password: str = "") -> str:
    """
    Extract message from a stego image.
    Raises ValueError with prefix 'PASSWORD_REQUIRED' if locked and no password given.
    Raises ValueError with prefix 'WRONG_PASSWORD' if password is wrong.
    """
    img    = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    pixels = list(img.getdata())

    bits = []
    for r, g, b in pixels:
        bits += [r & 1, g & 1, b & 1]

    raw = _from_bits(bits)

    # Encrypted path: starts with 4-byte length prefix + MAGIC
    if len(raw) >= 4 + len(PASSWORD_MAGIC):
        maybe_len = struct.unpack(">I", raw[:4])[0]
        end = 4 + maybe_len
        if end <= len(raw) and raw[4: 4 + len(PASSWORD_MAGIC)] == PASSWORD_MAGIC:
            if not password:
                raise ValueError(
                    "PASSWORD_REQUIRED: This image is password-protected."
                )
            enc_payload = raw[4:end]
            try:
                decrypted = _decrypt_payload(enc_payload, password)
            except ValueError:
                raise ValueError(
                    "WRONG_PASSWORD: Incorrect password. Please try again."
                )
            text = decrypted.decode("utf-8", errors="replace")
            if DELIMITER in text:
                return text.split(DELIMITER)[0]
            raise ValueError("Decryption succeeded but message format is invalid.")

    # Plain path
    text = raw.decode("utf-8", errors="replace")
    if DELIMITER in text:
        return text.split(DELIMITER)[0]

    raise ValueError(
        "No hidden message found in this image. "
        "Make sure you are using an image encoded with StegoVault."
    )


def is_password_protected(image_bytes: bytes) -> bool:
    """Return True if the image contains an encrypted (password-locked) payload."""
    try:
        img    = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        pixels = list(img.getdata())
        bits   = []
        needed = (4 + len(PASSWORD_MAGIC)) * 8
        for r, g, b in pixels:
            bits += [r & 1, g & 1, b & 1]
            if len(bits) >= needed:
                break
        raw = _from_bits(bits)
        if len(raw) >= 4 + len(PASSWORD_MAGIC):
            return raw[4: 4 + len(PASSWORD_MAGIC)] == PASSWORD_MAGIC
    except Exception:
        pass
    return False


def get_image_capacity(image_bytes: bytes) -> dict:
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    w, h = img.size
    total = w * h
    max_b = (total * 3) // 8
    return {
        "width": w, "height": h,
        "total_pixels": total,
        "max_bytes": max_b,
        "usable_chars": max(0, max_b - len(DELIMITER.encode())),
    }
