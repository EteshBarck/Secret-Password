import tkinter as tk
from tkinter import ttk
from pathlib import Path
from base64 import urlsafe_b64encode, urlsafe_b64decode

ACCENT = "#6366F1"
BG = "#0B1220"
CARD_BG = "#111827"
FG = "#E5E7EB"
MUTED = "#9CA3AF"

window = tk.Tk()
window.title("Secret Password")
window.geometry("380x560")
window.resizable(False, False)
window.configure(bg=BG)

style = ttk.Style()
style.theme_use("clam")

style.configure(".", foreground=FG, background=CARD_BG, font=("Segoe UI", 11))
style.configure("Title.TLabel", font=("Segoe UI Semibold", 22), background=BG, foreground=FG)
style.configure("Subtitle.TLabel", font=("Segoe UI", 12), background=CARD_BG, foreground=MUTED)
style.configure("Label.TLabel", font=("Segoe UI", 12), background=CARD_BG, foreground=FG)
style.configure("TEntry", fieldbackground="#0E1628", foreground=FG, insertcolor=FG, relief="flat")
style.map("TEntry", fieldbackground=[("focus", "#0F1B35")])
style.configure("Accent.TButton", font=("Segoe UI Semibold", 12), padding=8, background=ACCENT, foreground="white", relief="flat")
style.map("Accent.TButton", background=[("active", "#545CE8")])
style.configure("Ghost.TButton", font=("Segoe UI Semibold", 12), padding=8, background="#1F2937", foreground=FG, relief="flat")
style.map("Ghost.TButton", background=[("active", "#273244")])

card = tk.Frame(window, bg=CARD_BG, bd=0, highlightthickness=0)
card.place(relx=0.5, rely=0.5, anchor="center", width=330, height=460)

title = ttk.Label(window, text="Secret Password", style="Title.TLabel", background=BG)
title.place(relx=0.5, y=48, anchor="center")

header = ttk.Label(card, text="Create your password", style="Label.TLabel")
header.pack(pady=(22, 6))

subtitle = ttk.Label(card, text="Store an encrypted password, retrieve it with a hint.", style="Subtitle.TLabel", wraplength=280, justify="center")
subtitle.pack(pady=(0, 18))

password_header = ttk.Label(card, text="Password", style="Label.TLabel")
password_header.pack(anchor="w", padx=24)
password_entry = ttk.Entry(card, width=28, font=("Segoe UI", 12))
password_entry.pack(padx=24, pady=(6, 14))

hint_header = ttk.Label(card, text="Hint", style="Label.TLabel")
hint_header.pack(anchor="w", padx=24)
hint_entry = ttk.Entry(card, width=28, font=("Segoe UI", 12))
hint_entry.pack(padx=24, pady=(6, 18))

btn_row = tk.Frame(card, bg=CARD_BG)
btn_row.pack(pady=(6, 12))
save_button = ttk.Button(btn_row, text="Encryption", style="Accent.TButton", width=14)
save_button.pack(side="left", padx=(0, 8))
show_button = ttk.Button(btn_row, text="Decryption", style="Ghost.TButton", width=14)
show_button.pack(side="left", padx=(8, 0))

result_header = ttk.Label(card, text="Decrypted Result", style="Label.TLabel")
result_header.pack(anchor="w", padx=24, pady=(14, 6))
result_entry = ttk.Entry(card, width=32, font=("Segoe UI", 12), state="readonly")
result_entry.pack(padx=24)

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    o = bytearray()
    k = len(key)
    for i, b in enumerate(data):
        o.append(b ^ key[i % k])
    return bytes(o)

def encrypt_with_hint(plain_text: str, hint: str) -> str:
    c = _xor_bytes(plain_text.encode("utf-8"), hint.encode("utf-8"))
    return urlsafe_b64encode(c).decode("ascii")

def decrypt_with_hint(cipher_b64: str, hint: str) -> str:
    c = urlsafe_b64decode(cipher_b64.encode("ascii"))
    p = _xor_bytes(c, hint.encode("utf-8"))
    return p.decode("utf-8", errors="replace")

def show_password(msg: str):
    result_entry.config(state="normal")
    result_entry.delete(0, "end")
    result_entry.insert(0, msg)
    result_entry.config(state="readonly")

def save_password(p: str, h: str):
    if not p:
        show_password("Password cannot be empty.")
        return
    if not h:
        show_password("Please enter a hint.")
        return
    enc = encrypt_with_hint(p, h)
    fp = Path("secret.txt")
    with open(fp, "a+", encoding="utf-8") as f:
        f.write(f"{h}|{enc}\n")
    show_password("Saved.")

def load_and_decrypt(h: str):
    if not h:
        show_password("Please enter a hint.")
        return
    fp = Path("secret.txt")
    if not fp.exists():
        show_password("No records found.")
        return
    found = None
    with open(fp, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if "|" in line:
                hint, enc = line.split("|", 1)
                if hint == h:
                    found = decrypt_with_hint(enc, h)
                    break
    show_password(found if found is not None else "No record for this hint.")

save_button.configure(command=lambda: save_password(password_entry.get(), hint_entry.get()))
show_button.configure(command=lambda: load_and_decrypt(hint_entry.get()))

window.mainloop()
