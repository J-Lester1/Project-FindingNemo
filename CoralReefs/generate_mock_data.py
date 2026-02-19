import pandas as pd
import base64
import os
import random

# Configuration
CSV_FILE = "Nemo's.Memory.csv"
KEY_FILE = "MemoryKey.txt"

# Ensure key file exists
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(b"nexus_vault_secure_key_2024") 

key = open(KEY_FILE, "rb").read()

# Encryption Logic (copied from Namo.py)
def xor_data(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def shift_bytes(data, shift=3):
    return bytes([(b + shift) % 256 for b in data])

def unshift_bytes(data, shift=3):
    return bytes([(b - shift) % 256 for b in data])

def reverse_bytes(data):
    return data[::-1]

def encrypt_type(password, enc_type):
    data = password.encode('utf-8')
    if enc_type == 1: data = xor_data(data, key)
    elif enc_type == 2: data = reverse_bytes(xor_data(data, key))
    elif enc_type == 3: data = shift_bytes(xor_data(data, key))
    elif enc_type == 4: data = xor_data(xor_data(data, key), key[::-1])
    else: data = xor_data(data, key) 
    return base64.urlsafe_b64encode(data).decode('utf-8')

# Mock Data Generation
mock_data = [
    {"name": "Google", "url": "https://google.com", "username": "nemo@gmail.com", "password": "securepassword123"},
    {"name": "Facebook", "url": "https://facebook.com", "username": "nemo.fish", "password": "AnotherPassword456!"},
    {"name": "Twitter", "url": "https://twitter.com", "username": "@fishy_nemo", "password": "TweetTweett123"},
    {"name": "GitHub", "url": "https://github.com", "username": "codernemo", "password": "gitcommitpush"},
    {"name": "Bank of Atlantis", "url": "https://atlantisbank.sea", "username": "account_123456", "password": "SuperSecretBankPass"},
    {"name": "Amazon", "url": "https://amazon.com", "username": "shopper_fish", "password": "buyallthethings"},
    {"name": "Netflix", "url": "https://netflix.com", "username": "moviebuff", "password": "streamingaddict"},
    {"name": "Spotify", "url": "https://spotify.com", "username": "musiclover", "password": "playlistmaker"},
    {"name": "LinkedIn", "url": "https://linkedin.com", "username": "professional_nemo", "password": "networkexpert"},
    {"name": "Discord", "url": "https://discord.com", "username": "gamer_nemo#1234", "password": "discordnitro"}
]

rows = []
for item in mock_data:
    enc_type = random.randint(1, 4)
    enc_pass = encrypt_type(item["password"], enc_type)
    rows.append({
        "name": item["name"],
        "url": item["url"],
        "username": item["username"],
        "password": enc_pass,
        "encryption_type": enc_type
    })

df = pd.DataFrame(rows)
df.to_csv(CSV_FILE, index=False)
print(f"Generated {len(rows)} mock entries in '{CSV_FILE}'.")
