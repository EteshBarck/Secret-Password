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

OS: Windows, macOS, or Linux

You’ll receive a single .py file (no package). Create a virtual environment before running (recommended).

Quick Start
1) Create & activate a virtual environment

Windows (PowerShell):

py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1


macOS / Linux:

python3 -m venv .venv
source .venv/bin/activate


(No external packages needed; this step keeps your system Python clean.)

2) Run
python secret_password.py

Usage

Enter Password and Hint.

Click Encryption → saves hint|cipher to a local text file and hides it (where supported).

Enter the Hint and click Decryption → the original password appears in the Decrypted Result field.

Data File & Hiding Behavior

Default path: ./secret.txt

Format per line:

<hint>|<urlsafe_base64_of(xor(password, hint))>


Windows: file attribute is set to hidden.

macOS: chflags hidden is used.

Linux: rename to a dotfile (e.g., .secret.txt) if you want it hidden in most file managers.

Security Notice

This project uses XOR + Base64 for educational/demo purposes. It is not cryptographically secure. For real secrets, prefer a proper KDF (PBKDF2/Argon2) and authenticated encryption (AES-GCM).

Troubleshooting

Make sure your virtual environment is active before running.

If the UI fonts look off, you can switch to a font available on your system (e.g., replace "Segoe UI" with "Arial").

If the file doesn’t hide on Linux, rename it to .secret.txt.

License / Ownership

© 2025 ETESH BARCK. All rights reserved.
All rights to this project are owned by ETESH BARCK.
