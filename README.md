Secret Password (Tkinter)

A minimal desktop app built with Python + Tkinter to locally encrypt and retrieve passwords using a hint-based flow and a modern dark UI. Data is stored in a hidden text file next to the script.

Features

Dark, modern UI (custom ttk styles)

Encrypt & save a password with a hint

Decrypt by entering the same hint

Local storage in secret.txt (or hidden variant), one entry per line: hint|cipher

No third-party dependencies (standard library only)

Requirements

Python 3.9+

Windows, macOS, or Linux

You’ll receive a single .py file. Creating a virtual environment is recommended.

Quick Start
1) Create & activate a virtual environment

Windows (PowerShell):

py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1


macOS / Linux:

python3 -m venv .venv
source .venv/bin/activate

2) Run
python secret_password.py

Usage

Enter Password and Hint.

Click Encryption → saves hint|cipher to a local text file and hides it (where supported).

Enter the Hint and click Decryption → the original password appears in Decrypted Result.

Data File & Hiding

Path: ./secret.txt

Line format:

<hint>|<urlsafe_base64_of(xor(password, hint))>


Windows: hidden file attribute set.

macOS: chflags hidden used.

Linux: rename to .secret.txt if you want it hidden.

Security Notice

This uses XOR + Base64 for educational/demo purposes and is not cryptographically secure. For real secrets, use a proper KDF (PBKDF2/Argon2) and authenticated encryption (AES-GCM).

Troubleshooting

Ensure your virtual environment is active before running.

If fonts look off, replace "Segoe UI" with a font available on your system (e.g., "Arial").

On Linux, use a dotfile (.secret.txt) to hide.

License / Ownership

© 2025 ETESH BARCK. All rights reserved.
All rights to this project are owned by ETESH BARCK.
