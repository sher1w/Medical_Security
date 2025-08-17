import json, getpass, os, csv, logging
import bcrypt
from cryptography.fernet import Fernet
from datetime import datetime
import shutil
from datetime import datetime

import hashlib
import random

def send_otp():
    otp = str(random.randint(100000, 999999))
    print(f"OTP (demo): {otp}")  # In real use, send via email/SMS
    return otp

def get_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()


USERS_FILE = "users.json"
KEY_FILE = "secret.key"
CSV_FILE = "medical_data.csv"
LOG_FILE = "access.log"

# === Setup Logging ===
logging.basicConfig(filename=LOG_FILE, level=logging.INFO)

# === Authentication ===
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}

def login():
   users = load_users()
   username = input("Username: ")
   if username not in users:
        print("User not found.")
        return None
   otp = send_otp()
   entered = input("Enter OTP: ")
   if entered != otp:
        print("Invalid OTP. Login failed.")
        return None
   password = getpass.getpass("Password: ")
   hashed = users[username]["password"].encode()
   if bcrypt.checkpw(password.encode(), hashed):
        print("Login successful.")

        # ✅ Update last login
        users[username]["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=4)

        logging.info(f"{username} ({users[username]['role']}) logged in.")
        return username, users[username]["role"]
   else:
        print("Incorrect password.")
        return None

# === Encryption ===
def write_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)

def load_key():
    if not os.path.exists(KEY_FILE):
        write_key()
    with open(KEY_FILE, "rb") as f:
        return f.read()

def encrypt_data(data, key):
    return Fernet(key).encrypt(data.encode()).decode()

# === Main Function ===
def main():
    print("=== Medical Record Encryption ===")
    auth = login()
    if not auth:
        return
    username, role = auth

    if role not in ["doctor", "receptionist", "admin"]:
        print("You are not authorized to add data.")
        return

    # Collect patient data
    name = input("Patient Name: ")
    disease = input("Disease: ")
    prescription = input("Prescription: ")
    data = f"Name: {name}, Disease: {disease}, Prescription: {prescription}"

    key = load_key()
    encrypted = encrypt_data(data, key)
    # appending
    hash_val = get_hash(data)
    with open(CSV_FILE, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([encrypted, hash_val])

    print("Encrypted medical data saved.")
    logging.info(f"{username} ({role}) added record for patient: {name}")
    backup_name = f"backup/medical_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    os.makedirs("backup", exist_ok=True); shutil.copy(CSV_FILE, backup_name)
    print(f"Backup created: {backup_name}")


if __name__ == "__main__":
    main()
