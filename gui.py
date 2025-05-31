import tkinter as tk
from tkinter import filedialog, messagebox
from tkinterdnd2 import DND_FILES, TkinterDnD
from cryptography.fernet import Fernet
import os
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

 # Helper Functions 

def generate_key_from_password(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password_bytes))

def save_log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("encryption_log.txt", "a") as log_file:
        log_file.write(f"[{timestamp}] {message}\n")

# Encryption/Decryption Logic

def encrypt_file():
    try:
        file_path = file_path_var.get()
        password = password_var.get()
        confirm = confirm_var.get()
        save_location = save_location_var.get()

        if password != confirm:
            messagebox.showerror("Password Mismatch", "Passwords do not match!")
            return

        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please choose a valid file.")
            return

        salt = os.urandom(16)
        key = generate_key_from_password(password, salt)
        cipher = Fernet(key)

        with open(file_path, "rb") as file:
            data = file.read()

        encrypted = cipher.encrypt(data)

        output_path = os.path.join(save_location, os.path.basename(file_path) + ".enc")
        with open(output_path, "wb") as out_file:
            out_file.write(salt + encrypted)

        save_log(f"Encrypted: {file_path} -> {output_path}")
        messagebox.showinfo("Success", "File encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_file():
    try:
        file_path = file_path_var.get()
        password = password_var.get()
        save_location = save_location_var.get()

        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please choose a valid file.")
            return

        with open(file_path, "rb") as file:
            file_data = file.read()

        salt = file_data[:16]
        encrypted_data = file_data[16:]

        key = generate_key_from_password(password, salt)
        cipher = Fernet(key)

        decrypted = cipher.decrypt(encrypted_data)

        output_path = os.path.join(save_location, os.path.basename(file_path).replace(".enc", "_dec"))
        with open(output_path, "wb") as out_file:
            out_file.write(decrypted)

        save_log(f"Decrypted: {file_path} -> {output_path}")
        messagebox.showinfo("Success", "File decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI Setup

root = TkinterDnD.Tk()
root.title("SafeVault - Dunal")
root.geometry("620x520")
root.configure(bg="#f2f2f2")

# Variables

file_path_var = tk.StringVar()
password_var = tk.StringVar()
confirm_var = tk.StringVar()
save_location_var = tk.StringVar(value=os.getcwd())

# Style

style_font = ("Segoe UI", 11)
entry_bg = "#ffffff"
entry_fg = "#000000"
button_bg = "#4CAF50"
button_fg = "#ffffff"
accent_color = "#0078D4"

# Layout

tk.Label(root, text="SafeVault", font=("Segoe UI", 22, "bold"), fg=accent_color, bg="#f2f2f2").pack(pady=20)

def choose_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_path_var.set(file_path)

def choose_folder():
    folder = filedialog.askdirectory()
    if folder:
        save_location_var.set(folder)

form_frame = tk.Frame(root, bg="#f2f2f2")
form_frame.pack(pady=10)

# File Path
tk.Label(form_frame, text="File Path:", font=style_font, bg="#f2f2f2").grid(row=0, column=0, sticky="e")
tk.Entry(form_frame, textvariable=file_path_var, width=40, font=style_font, bg=entry_bg, fg=entry_fg).grid(row=0, column=1, padx=5)
tk.Button(form_frame, text="Browse", command=choose_file, bg=accent_color, fg="white").grid(row=0, column=2, padx=5)

root.drop_target_register(DND_FILES)
root.dnd_bind('<<Drop>>', lambda e: file_path_var.set(e.data.strip('{}')))

# Password
tk.Label(form_frame, text="Password:", font=style_font, bg="#f2f2f2").grid(row=1, column=0, sticky="e")
tk.Entry(form_frame, textvariable=password_var, show="*", width=40, font=style_font, bg=entry_bg, fg=entry_fg).grid(row=1, column=1, padx=5)

# Confirm Password
tk.Label(form_frame, text="Confirm Password:", font=style_font, bg="#f2f2f2").grid(row=2, column=0, sticky="e")
tk.Entry(form_frame, textvariable=confirm_var, show="*", width=40, font=style_font, bg=entry_bg, fg=entry_fg).grid(row=2, column=1, padx=5)

# Save Location
tk.Label(form_frame, text="Save Location:", font=style_font, bg="#f2f2f2").grid(row=3, column=0, sticky="e")
tk.Entry(form_frame, textvariable=save_location_var, width=40, font=style_font, bg=entry_bg, fg=entry_fg).grid(row=3, column=1, padx=5)
tk.Button(form_frame, text="Choose", command=choose_folder, bg=accent_color, fg="white").grid(row=3, column=2, padx=5)

# Buttons
btn_frame = tk.Frame(root, bg="#f2f2f2")
btn_frame.pack(pady=30)

tk.Button(btn_frame, text="Encrypt", command=encrypt_file, bg="#0078D4", fg="white", font=style_font, width=18).pack(side="left", padx=15)
tk.Button(btn_frame, text="Decrypt", command=decrypt_file, bg="#E81123", fg="white", font=style_font, width=18).pack(side="right", padx=15)

root.mainloop()
