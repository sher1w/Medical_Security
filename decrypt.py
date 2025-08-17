import json, getpass, os, csv, logging
import bcrypt
from cryptography.fernet import Fernet
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

# === Decryption ===
def load_key():
    if not os.path.exists(KEY_FILE):
        print("Encryption key not found.")
        exit()
    with open(KEY_FILE, "rb") as f:
        return f.read()

def decrypt_data(encrypted_data, key):
    return Fernet(key).decrypt(encrypted_data.encode()).decode()

# === Main Function ===
def main():
    print("=== Medical Record Viewer ===")
    auth = login()
    if not auth:
        return
    username, role = auth

    key = load_key()

    if not os.path.exists(CSV_FILE):
        print("No medical records found.")
        return

    print("\n--- Decrypted Medical Records ---")
    with open(CSV_FILE, "r") as file:
        reader = csv.reader(file)
        for i, row in enumerate(reader, start=1):
            if row:
                try:
                    decrypted = decrypt_data(row[0].strip(), key)
                    stored_hash = row[1].strip()
                    current_hash = get_hash(decrypted)

                    # ✅ Role-based access control here
                    if role == "patient" and username not in decrypted:
                        continue  # skip other patients' records
                    # doctors/admin see all → no filter

                    if stored_hash == current_hash:
                        print(f"\nRecord {i}: {decrypted} ✅ (Integrity Verified)")
                    else:
                        print(f"\nRecord {i}: {decrypted} ⚠️ (Integrity FAILED)")

                except Exception as e:
                    logging.error(f"Error decrypting record {i}: {e}")

    # ✅ Logging after viewing
    logging.info(f"{username} ({role}) viewed medical records.")


if __name__ == "__main__":
    main()
