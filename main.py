import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import os


# =========================================================
# PASSWORD -> ENCRYPTION KEY
# =========================================================

def make_key(password, salt):
    """
    Password ko secure encryption key me convert karta hai.
    """

    password_bytes = password.encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )

    key = base64.urlsafe_b64encode(
        kdf.derive(password_bytes)
    )

    return key


# =========================================================
# ENCRYPT FILE
# =========================================================

def encrypt_file():

    file_path = filedialog.askopenfilename(
        title="Select File to Encrypt"
    )

    if not file_path:
        return

    selected_file.set("Selected: " + file_path)

    password = password_entry.get()

    if not password:
        messagebox.showwarning(
            "Warning",
            "Enter a password first."
        )
        return

    # Agar file already encrypted hai
    if file_path.endswith(".enc"):
        messagebox.showwarning(
            "Warning",
            "This file is already encrypted."
        )
        return

    try:

        # Random salt
        salt = os.urandom(16)

        # Password se key
        key = make_key(password, salt)

        cipher = Fernet(key)

        # Original file read
        with open(file_path, "rb") as file:
            data = file.read()

        # Encrypt
        encrypted_data = cipher.encrypt(data)

        # Salt + encrypted data
        final_data = salt + encrypted_data

        # New encrypted file
        output_path = file_path + ".enc"

        # Pehle encrypted file safely create karo
        with open(output_path, "wb") as file:
            file.write(final_data)

        # Verify encrypted file exists and has data
        if not os.path.exists(output_path):
            raise Exception("Encrypted file could not be created.")

        if os.path.getsize(output_path) == 0:
            raise Exception("Encrypted file is empty.")

        # IMPORTANT:
        # Original plaintext file delete hoga
        os.remove(file_path)

        status_label.config(
            text="✓ File encrypted and original removed"
        )

        messagebox.showinfo(
            "Success",
            "File encrypted successfully.\n\n"
            "Original file has been removed.\n"
            "Only the .enc encrypted file remains."
        )

    except Exception as error:

        # Agar encryption ke beech error aaya
        # to original file ko delete nahi karenge.

        messagebox.showerror(
            "Encryption Error",
            str(error)
        )


# =========================================================
# DECRYPT FILE
# =========================================================

def decrypt_file():

    file_path = filedialog.askopenfilename(
        title="Select Encrypted File",
        filetypes=[
            ("Encrypted Files", "*.enc")
        ]
    )

    if not file_path:
        return

    selected_file.set("Selected: " + file_path)

    password = password_entry.get()

    if not password:
        messagebox.showwarning(
            "Warning",
            "Enter a password first."
        )
        return

    # Check .enc extension
    if not file_path.endswith(".enc"):
        messagebox.showwarning(
            "Warning",
            "Please select a .enc encrypted file."
        )
        return

    try:

        # Encrypted file read
        with open(file_path, "rb") as file:
            encrypted_file_data = file.read()

        # Minimum size check
        if len(encrypted_file_data) <= 16:
            raise ValueError(
                "Invalid encrypted file."
            )

        # First 16 bytes = salt
        salt = encrypted_file_data[:16]

        # Remaining = Fernet encrypted data
        encrypted_data = encrypted_file_data[16:]

        # Password se same key generate
        key = make_key(password, salt)

        cipher = Fernet(key)

        # Decrypt
        decrypted_data = cipher.decrypt(
            encrypted_data
        )

        # Original file name
        output_path = file_path[:-4]

        # Agar original file already exists
        if os.path.exists(output_path):

            overwrite = messagebox.askyesno(
                "File Already Exists",
                "A file with this name already exists.\n\n"
                "Do you want to replace it?"
            )

            if not overwrite:
                return

        # Temporary file first
        temp_path = output_path + ".tmp"

        with open(temp_path, "wb") as file:
            file.write(decrypted_data)

        # Check temporary file
        if not os.path.exists(temp_path):
            raise Exception(
                "Could not create decrypted file."
            )

        # Replace/create original file
        os.replace(
            temp_path,
            output_path
        )

        # IMPORTANT:
        # Sirf successful decryption ke baad .enc delete
        os.remove(file_path)

        status_label.config(
            text="✓ File decrypted successfully"
        )

        messagebox.showinfo(
            "Success",
            "File decrypted successfully.\n\n"
            "Original file has been restored."
        )

    except InvalidToken:

        # Wrong password
        status_label.config(
            text="✗ Wrong password"
        )

        messagebox.showerror(
            "Decrypt Error",
            "Wrong password or invalid encrypted file."
        )

    except Exception as error:

        status_label.config(
            text="✗ Decryption failed"
        )

        # Temporary file agar bana ho to remove
        temp_path = file_path[:-4] + ".tmp"

        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass

        messagebox.showerror(
            "Decrypt Error",
            str(error)
        )


# =========================================================
# CLEAR
# =========================================================

def clear_all():

    password_entry.delete(
        0,
        tk.END
    )

    selected_file.set(
        "No file selected"
    )

    status_label.config(
        text="Ready"
    )


# =========================================================
# GUI
# =========================================================

root = tk.Tk()

root.title(
    "Secure File Vault"
)

root.geometry(
    "500x430"
)

root.resizable(
    False,
    False
)


# =========================================================
# TITLE
# =========================================================

title_label = tk.Label(
    root,
    text="🔐 Secure File Vault",
    font=("Arial", 24, "bold")
)

title_label.pack(
    pady=30
)


# =========================================================
# PASSWORD
# =========================================================

password_label = tk.Label(
    root,
    text="Password:",
    font=("Arial", 12)
)

password_label.pack()


password_entry = tk.Entry(
    root,
    show="*",
    width=30,
    font=("Arial", 12)
)

password_entry.pack(
    pady=10
)


# =========================================================
# SELECTED FILE
# =========================================================

selected_file = tk.StringVar(
    value="No file selected"
)

file_label = tk.Label(
    root,
    textvariable=selected_file,
    font=("Arial", 10),
    wraplength=400,
    justify="center"
)

file_label.pack(
    pady=5
)


# =========================================================
# ENCRYPT BUTTON
# =========================================================

encrypt_button = tk.Button(
    root,
    text="🔒 Encrypt File",
    command=encrypt_file,
    width=25,
    height=2,
    font=("Arial", 11)
)

encrypt_button.pack(
    pady=10
)


# =========================================================
# CLEAR BUTTON
# =========================================================

clear_button = tk.Button(
    root,
    text="Clear",
    command=clear_all,
    width=25,
    height=2,
    font=("Arial", 11)
)

clear_button.pack(
    pady=10
)


# =========================================================
# DECRYPT BUTTON
# =========================================================

decrypt_button = tk.Button(
    root,
    text="🔓 Decrypt File",
    command=decrypt_file,
    width=25,
    height=2,
    font=("Arial", 11)
)

decrypt_button.pack(
    pady=10
)


# =========================================================
# STATUS
# =========================================================

status_label = tk.Label(
    root,
    text="Ready",
    font=("Arial", 11)
)

status_label.pack(
    pady=20
)


# =========================================================
# START APP
# =========================================================

root.mainloop()
