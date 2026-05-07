# StegoVault — Django Image Steganography App

Hide and reveal secret text messages inside ordinary images using
**Least Significant Bit (LSB)** steganography.

## New Features (v2)

| Feature | Details |
|---|---|
| **Password Lock** | AES-256-GCM encryption via PBKDF2-SHA256 key derivation |
| **Password Strength Meter** | Real-time bar while typing |
| **Password Pop-up Modal** | Auto-detects locked images; shows a dialog on upload |
| **Export as TXT** | Download decoded message as a plain-text `.txt` file |
| **Export as PDF** | Download decoded message as a styled, timestamped PDF |
| **Lock Detection** | AJAX endpoint checks if an image is password-protected before submission |

---

## Quick Start

```bash
cd stego_app

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt

python manage.py migrate
python manage.py runserver
```

Open `http://127.0.0.1:8000/`

---

## Encryption Details

When a password is provided:

1. A 16-byte random **salt** and 12-byte **nonce** are generated.
2. A 32-byte key is derived via **PBKDF2-SHA256** (200,000 iterations).
3. The payload is encrypted with **AES-256-GCM** (authenticated).
4. The ciphertext is prefixed with a 4-byte length header + `0xDEADBEEF` magic marker.
5. The whole blob is LSB-embedded into the image pixels.

Without `cryptography` installed, a PBKDF2-derived XOR stream + HMAC-SHA256 tag is used as a fallback.

---

## Project Structure

```
stego_app/
├── config/            Django settings, urls, wsgi
├── stego/
│   ├── engine.py      LSB + AES-256-GCM crypto engine
│   ├── forms.py       Upload + password forms
│   ├── views.py       Encode, Decode, Export TXT/PDF, AJAX endpoints
│   ├── urls.py        URL routing
│   └── templates/stego/
│       ├── base.html  Dark industrial theme + modal styles
│       ├── index.html Landing page
│       ├── encode.html Password toggle switch + strength meter
│       └── decode.html Lock detection + password modal + export buttons
├── requirements.txt
└── manage.py
```

---

## Notes

- **Use PNG or BMP** — JPEG compression destroys LSB data.
- Encoded images are always saved as **PNG**.
- The `cryptography` package is optional but strongly recommended for production.
- `reportlab` is required for PDF export.
- Change `SECRET_KEY` in `config/settings.py` before deploying.
