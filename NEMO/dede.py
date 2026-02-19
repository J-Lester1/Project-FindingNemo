import base64

# Load key
key = open("encryption_key.txt", "rb").read()

# ---------- BASIC OPERATIONS ----------

def xor_data(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def shift_bytes(data, shift=3):
    return bytes([(b - shift) % 256 for b in data])

def unshift_bytes(data, shift=3):
    return bytes([(b + shift) % 256 for b in data])

# ---------- DECRYPTION TYPES ----------

def decrypt_type(enc_text, enc_type):

    data = base64.urlsafe_b64decode(enc_text.encode())

    if enc_type == 1:
        data = xor_data(data, key)

    elif enc_type == 2:
        data = data[::-1]
        data = xor_data(data, key)

    elif enc_type == 3:
        data = shift_bytes(data)
        data = xor_data(data, key)

    elif enc_type == 4:
        data = xor_data(data, key[::-1])
        data = xor_data(data, key)

    elif enc_type == 5:
        data = xor_data(data, key[::-1])

    elif enc_type == 6:
        data = xor_data(data, key)
        data = shift_bytes(data)

    elif enc_type == 7:
        data = base64.urlsafe_b64decode(data)
        data = xor_data(data, key)

    elif enc_type == 8:
        half = len(data) // 2
        data = data[half:] + data[:half]
        data = xor_data(data, key)

    elif enc_type == 9:
        data = shift_bytes(data)

    elif enc_type == 10:
        data = data[1:] + data[:1]
        data = xor_data(data, key)

    else:
        raise ValueError("Unknown encryption type")

    return data.decode()

# ---------- USER INPUT ----------

enc_password = input("Enter encrypted password: ")
enc_type = int(input("Enter encryption type (1-10): "))

print("Decrypted password:", decrypt_type(enc_password, enc_type))
