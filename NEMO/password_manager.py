import pandas as pd
import base64
import os

CSV_FILE = "accounts_encrypted.csv"
KEY_FILE = "encryption_key.txt"

# ---------------- LOAD KEY ----------------
if not os.path.exists(KEY_FILE):
    print("❌ encryption_key.txt not found!")
    exit()

key = open(KEY_FILE, "rb").read()

# ---------------- BASIC OPS ----------------

def xor_data(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def shift_bytes(data, shift=3):
    return bytes([(b + shift) % 256 for b in data])

def unshift_bytes(data, shift=3):
    return bytes([(b - shift) % 256 for b in data])

def reverse_bytes(data):
    return data[::-1]

def swap_halves(data):
    half = len(data) // 2
    return data[half:] + data[:half]

def rotate_left(data):
    return data[1:] + data[:1]

def rotate_right(data):
    return data[-1:] + data[:-1]

# ---------------- ENCRYPT ----------------

def encrypt_type(password, enc_type):
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

    return base64.urlsafe_b64encode(data).decode()

# ---------------- DECRYPT ----------------

def decrypt_type(enc_text, enc_type):
    data = base64.urlsafe_b64decode(enc_text.encode())

    if enc_type == 1:
        data = xor_data(data, key)

    elif enc_type == 2:
        data = reverse_bytes(data)
        data = xor_data(data, key)

    elif enc_type == 3:
        data = unshift_bytes(data)
        data = xor_data(data, key)

    elif enc_type == 4:
        data = xor_data(data, key[::-1])
        data = xor_data(data, key)

    elif enc_type == 5:
        data = xor_data(data, key[::-1])

    elif enc_type == 6:
        data = xor_data(data, key)
        data = unshift_bytes(data)

    elif enc_type == 7:
        data = base64.urlsafe_b64decode(data)
        data = xor_data(data, key)

    elif enc_type == 8:
        half = len(data) // 2
        data = data[half:] + data[:half]
        data = xor_data(data, key)

    elif enc_type == 9:
        data = unshift_bytes(data)

    elif enc_type == 10:
        data = rotate_right(data)
        data = xor_data(data, key)

    return data.decode()

# ---------------- LOAD CSV ----------------

def load_data():
    if os.path.exists(CSV_FILE):
        return pd.read_csv(CSV_FILE)
    else:
        return pd.DataFrame(columns=["name", "url", "username", "password", "encryption_type"])

def save_data(df):
    df.to_csv(CSV_FILE, index=False)

# ---------------- FEATURES ----------------

def add_account():
    df = load_data()

    name = input("Account Name: ")
    url = input("URL: ")
    username = input("Username: ")
    password = input("Password: ")

    enc_type = int(input("Encryption type (1-10): "))
    enc_password = encrypt_type(password, enc_type)

    new_row = {
        "name": name,
        "url": url,
        "username": username,
        "password": enc_password,
        "encryption_type": enc_type
    }

    df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
    save_data(df)

    print("✅ Account added!\n")

def view_accounts():
    df = load_data()
    print("\n==== SAVED ACCOUNTS ====")
    print(df[["name", "url", "username", "encryption_type"]])
    print()

def decrypt_password():
    df = load_data()

    index = int(input("Enter row index to decrypt: "))
    row = df.iloc[index]

    password = decrypt_type(row["password"], int(row["encryption_type"]))

    print("🔓 Decrypted Password:", password)

def search_account():
    df = load_data()

    keyword = input("Search keyword: ").lower()

    results = df[df["name"].str.lower().str.contains(keyword)]
    print(results[["name", "url", "username", "encryption_type"]])

def edit_account():
    df = load_data()

    index = int(input("Enter row index to edit: "))
    row = df.iloc[index]

    print("Leave blank to keep old value")

    name = input(f"Name ({row['name']}): ") or row["name"]
    url = input(f"URL ({row['url']}): ") or row["url"]
    username = input(f"Username ({row['username']}): ") or row["username"]

    change_pass = input("Change password? (y/n): ")

    if change_pass.lower() == "y":
        password = input("New password: ")
        enc_type = int(input("Encryption type (1-10): "))
        enc_password = encrypt_type(password, enc_type)
    else:
        enc_password = row["password"]
        enc_type = row["encryption_type"]

    df.loc[index] = [name, url, username, enc_password, enc_type]
    save_data(df)

    print("✅ Account updated!\n")

# ---------------- MENU ----------------

def menu():
    while True:
        print("""
1 - Add account
2 - View accounts
3 - Decrypt password
4 - Search
5 - Edit account
0 - Exit
""")

        choice = input("Choose: ")

        if choice == "1":
            add_account()
        elif choice == "2":
            view_accounts()
        elif choice == "3":
            decrypt_password()
        elif choice == "4":
            search_account()
        elif choice == "5":
            edit_account()
        elif choice == "0":
            break
        else:
            print("Invalid choice")

menu()
