import tkinter as tk
from tkinter import messagebox
import base64

def show_main_screen():
    main_screen = tk.Toplevel(root)
    main_screen.title("SecApp")
    main_screen.geometry("400x300")

    # Create and place widgets
    label_message = tk.Label(main_screen, text="Message:", font=("Helvetica", 12, "bold"))
    label_message.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

    entry_message = tk.Entry(main_screen, width=50, font=("Helvetica", 10))
    entry_message.grid(row=0, column=1, padx=5, pady=5)

    label_encrypted = tk.Label(main_screen, text="Encrypted:", font=("Helvetica", 12, "bold"))
    label_encrypted.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)

    entry_encrypted = tk.Entry(main_screen, width=50, font=("Helvetica", 10))
    entry_encrypted.grid(row=1, column=1, padx=5, pady=5)

    label_decrypted = tk.Label(main_screen, text="Decrypted:", font=("Helvetica", 12, "bold"))
    label_decrypted.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)

    entry_decrypted = tk.Entry(main_screen, width=50, font=("Helvetica", 10))
    entry_decrypted.grid(row=2, column=1, padx=5, pady=5)

    button_encrypt = tk.Button(main_screen, text="Encrypt", command=lambda: encrypt_message(entry_message, entry_encrypted),
                                bg="#4CAF50", fg="white", font=("Helvetica", 12, "bold"))
    button_encrypt.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W + tk.E)

    button_decrypt = tk.Button(main_screen, text="Decrypt", command=lambda: decrypt_message(entry_encrypted, entry_decrypted),
                                bg="#008CBA", fg="white", font=("Helvetica", 12, "bold"))
    button_decrypt.grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W + tk.E)

    button_clear = tk.Button(main_screen, text="Clear", command=lambda: clear_entries(entry_message, entry_encrypted, entry_decrypted),
                              bg="#f44336", fg="white", font=("Helvetica", 12, "bold"))
    button_clear.grid(row=5, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W + tk.E)


def verify_password():
    password = password_entry.get()
    if password == "1234":
        show_main_screen()
        password_screen.destroy()
    else:
        messagebox.showerror("Error", "Invalid password.")


def encrypt_message(entry_message, entry_encrypted):
    message = entry_message.get()
    if not message:
        messagebox.showerror("Error", "Please enter a message to encrypt.")
        return

    encoded_message = base64.b64encode(message.encode("utf-8"))
    entry_encrypted.delete(0, tk.END)
    entry_encrypted.insert(0, encoded_message.decode("utf-8"))


def decrypt_message(entry_encrypted, entry_decrypted):
    encrypted_message = entry_encrypted.get()
    if not encrypted_message:
        messagebox.showerror("Error", "Please enter an encrypted message to decrypt.")
        return

    try:
        decoded_message = base64.b64decode(encrypted_message.encode("utf-8"))
        entry_decrypted.delete(0, tk.END)
        entry_decrypted.insert(0, decoded_message.decode("utf-8"))
    except Exception as e:
        messagebox.showerror("Error", "Invalid encrypted message.")


def clear_entries(entry_message, entry_encrypted, entry_decrypted):
    entry_message.delete(0, tk.END)
    entry_encrypted.delete(0, tk.END)
    entry_decrypted.delete(0, tk.END)


# Create main window
root = tk.Tk()
root.title("SecApp")

# Password Screen
password_screen = tk.Toplevel(root)
password_screen.title("Password")
password_screen.geometry("300x150")

label_password = tk.Label(password_screen, text="Enter Password:", font=("Helvetica", 14))
label_password.grid(row=0, column=0, padx=5, pady=10)

password_entry = tk.Entry(password_screen, width=20, show="*", font=("Helvetica", 12))
password_entry.grid(row=1, column=0, padx=5, pady=5)

button_verify = tk.Button(password_screen, text="Verify", command=verify_password,
                          bg="#008CBA", fg="white", font=("Helvetica", 12, "bold"))
button_verify.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W + tk.E)

# Run the application
root.mainloop()
