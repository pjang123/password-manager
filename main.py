#created by Paul Jang
#Date: 07/16/2024
#Description: a simple password manager to store, view, and remove passwords that are encrypted using AES-128 encryption. 

import os
import base64
import tkinter as tk
from tkinter import simpledialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def generate_key():
    # generates a 128-bit key for AES-128
    key = os.urandom(16)
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("secret.key", "rb").read()

# Uncomment the line below to generate a key the first time you run the program
# generate_key()

key = load_key()

def encrypt_password(password):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(password.encode()) + padder.finalize()
    encrypted_password = encryptor.update(padded_data) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + encrypted_password).decode()

def decrypt_password(encrypted_password):
    data = base64.urlsafe_b64decode(encrypted_password)
    iv = data[:16]
    encrypted_password = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = decryptor.update(encrypted_password) + decryptor.finalize()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode()

def add_password(service, username, password):
    encrypted_password = encrypt_password(password)
    with open("passwords.txt", "a") as f:
        f.write(f"{service},{username},{encrypted_password}\n")

def get_password(service):
    with open("passwords.txt", "r") as f:
        for line in f.readlines():
            data = line.strip().split(",")
            if data[0] == service:
                username = data[1]
                decrypted_password = decrypt_password(data[2])
                return username, decrypted_password
    return None, None

def list_services():
    services = set()
    if os.path.exists("passwords.txt"):
        with open("passwords.txt", "r") as f:
            for line in f.readlines():
                data = line.strip().split(",")
                services.add(data[0])
    return services

def remove_service(service):
    with open("passwords.txt", "r") as f:
        lines = f.readlines()
    with open("passwords.txt", "w") as f:
        for line in lines:
            data = line.strip().split(",")
            if data[0] != service:
                f.write(line)

def add_password_gui():
    service = simpledialog.askstring("Input", "Enter the service:")
    username = simpledialog.askstring("Input", "Enter the username:")
    password = simpledialog.askstring("Input", "Enter the password:", show='*')
    if service and username and password:
        add_password(service, username, password)
        messagebox.showinfo("Success", "Password added successfully!")

def get_password_gui():
    service = simpledialog.askstring("Input", "Enter the service:")
    if service:
        username, password = get_password(service)
        if username:
            messagebox.showinfo("Password", f"Username: {username}\nPassword: {password}")
        else:
            messagebox.showwarning("Error", "No password found for this service.")

def list_services_gui():
    services = list_services()
    if services:
        messagebox.showinfo("Services", "\n".join(services))
    else:
        messagebox.showwarning("Error", "No services found.")

def remove_service_gui():
    service = simpledialog.askstring("Input", "Enter the service to remove:")
    services = list_services()
    if service in services:
        remove_service(service)
        messagebox.showinfo("Success", f"Service '{service}' removed successfully!")
    else:
        messagebox.showwarning("Error", "Please enter a valid service name.")

def main():
    root = tk.Tk()
    root.title("Password Manager")
    root.geometry("200x250")

    add_button = tk.Button(root, text="Add Password", command=add_password_gui)
    add_button.pack(pady=10)

    get_button = tk.Button(root, text="Get Password", command=get_password_gui)
    get_button.pack(pady=10)

    list_button = tk.Button(root, text="List Services", command=list_services_gui)
    list_button.pack(pady=10)

    remove_button = tk.Button(root, text="Remove Service", command=remove_service_gui)
    remove_button.pack(pady=10)

    exit_button = tk.Button(root, text="Exit", command=root.quit)
    exit_button.pack(pady=10)

    

    root.mainloop()

if __name__ == "__main__":
    main()
