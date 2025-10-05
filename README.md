# Secret Password (Tkinter)

A minimal desktop app built with **Python + Tkinter** to locally encrypt and retrieve passwords using a **hint-based** flow and a **modern dark UI**. Data is stored in a **hidden** text file next to the script.

## Features
- Dark, modern UI (custom `ttk` styles)
- **Encrypt & save** with a **hint**
- **Decrypt** by entering the same hint
- Local storage in `secret.txt` (`hint|cipher`)
- No third-party dependencies

## Requirements
- **Python 3.9+**
- Windows, macOS, or Linux
- You’ll receive a single `.py` file; using a virtual environment is recommended.

## Quick Start
### 1) Create & activate venv
**Windows (PowerShell):**
```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
macOS / Linux:

bash
Copy code
python3 -m venv .venv
source .venv/bin/activate
2) Run
bash
Copy code
python secret_password.py
Data File & Hiding
Path: ./secret.txt

Line format:

perl
Copy code
<hint>|<urlsafe_base64_of(xor(password, hint))>
Windows: hidden attribute set

macOS: chflags hidden

Linux: rename to .secret.txt to hide

Security Notice
Uses XOR + Base64 for demo; not cryptographically secure. For real secrets use PBKDF2/Argon2 + AES-GCM.

License / Ownership
© 2025 ETESH BARCK. All rights reserved.
All rights to this project are owned by ETESH BARCK.
