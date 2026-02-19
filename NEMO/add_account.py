import pandas as pd
import base64
import os

# ---------------- LOAD KEY ----------------
KEY_FILE = "encryption_key.txt"

if not os.path.exists(KEY_FILE):
    print("❌ encryption_key.txt not found!")
    exit()

key = open(KEY_FILE, "rb").read()

# ---------------- BASIC OPERATIONS ----------------

def xor_data(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def shift_bytes(data, shift=3):
    return bytes([(b + shift) % 256 for b in data])

def reverse_bytes(data):
    return data[::-1]

def swap_halves(data):
    half = len(data) // 2
    return data[half:] + data[:half]

def rotate_left(data):
    return data[1:] + data[:1]

# ---------------- ENCRYPTION TYPES ----------------

def encrypt_type(password, enc_type, key):
    data = password.encode()

    if enc_type == 1:
        data = xor_data(data, key)

    elif enc_type == 2:
        data = xor_data(data, key)
        data = reverse_bytes(data)

    elif enc_type == 3:
        data = xor_data(data, key)
        data = shift_bytes(data)

    elif enc_type == 4:
        data = xor_data(data, key)
        data = xor_data(data, key[::-1])

    elif enc_type == 5:
        data = xor_data(data, key[::-1])

    elif enc_type == 6:
        data = shift_bytes(data)
        data = xor_data(data, key)

    elif enc_type == 7:
        data = xor_data(data, key)
        data = base64.urlsafe_b64encode(data)
        return base64.urlsafe_b64encode(data).decode()

    elif enc_type == 8:
        data = xor_data(data, key)
        data = swap_halves(data)

    elif enc_type == 9:
        data = shift_bytes(data)

    elif enc_type == 10:
        data = xor_data(data, key)
        data = rotate_left(data)

    else:
        raise ValueError("Invalid encryption type")

    return base64.urlsafe_b64encode(data).decode()

# ---------------- LOAD OR CREATE CSV ----------------

CSV_FILE = "accounts_encrypted.csv"

if os.path.exists(CSV_FILE):
    df = pd.read_csv(CSV_FILE)
else:
    df = pd.DataFrame(columns=["name", "url", "username", "password", "encryption_type"])

# ---------------- USER INPUT ----------------

print("==== ADD NEW ACCOUNT ====")

name = input("Account Name: ")
url = input("URL: ")
username = input("Username: ")
password = input("Password: ")

print("\nChoose Encryption Type (1-10):")
for i in range(1, 11):
    print(f"{i} - Encryption Type {i}")

enc_type = int(input("Enter choice: "))

# ---------------- ENCRYPT ----------------

enc_password = encrypt_type(password, enc_type, key)

# ---------------- SAVE ----------------

new_row = {
    "name": name,
    "url": url,
    "username": username,
    "password": enc_password,
    "encryption_type": enc_type
}

df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
df.to_csv(CSV_FILE, index=False)

print("\n✅ Account saved successfully with encryption!")
