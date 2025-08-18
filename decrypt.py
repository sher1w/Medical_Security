import json, getpass, os, csv, logging
import bcrypt
from cryptography.fernet import Fernet
from datetime import datetime
import hashlib
from audit import write_entry   # ✅ Audit log support


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

    # 🔒 Check if account is locked
    if users[username].get("locked", False):
        print("Account locked due to multiple failed login attempts. Contact admin.")
        return None

    password = getpass.getpass("Password: ")
    hashed = users[username]["password"].encode()

    if bcrypt.checkpw(password.encode(), hashed):
        print("Login successful.")

        # ✅ Fetch role immediately
        role = users[username]["role"]

        # ✅ Reset failed attempts on success
        users[username]["failed_attempts"] = 0
        users[username]["locked"] = False
        users[username]["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=4)

        logging.info(f"{username} ({role}) logged in.")
        write_entry("login", "success", username, role)   # ✅ Single login log

        return username, role
    else:
        print("Incorrect password.")

        # Increment failed attempts
        users[username]["failed_attempts"] = users[username].get("failed_attempts", 0) + 1
        if users[username]["failed_attempts"] >= 3:
            users[username]["locked"] = True
            print("Account locked due to too many failed attempts.")

        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=4)

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

    # Search options (doctors & admins only)
    search_mode = None
    search_query = None
    if role in ["doctor", "admin"]:
        choice = input("Do you want to (a) view all records or (b) search? ").lower()
        if choice == "b":
            search_mode = input("Search by (name/disease): ").lower()
            search_query = input("Enter search term: ").lower()

    key = load_key()

    if not os.path.exists(CSV_FILE):
        print("No medical records found.")
        return

    print("\n--- Decrypted Medical Records ---")
    with open(CSV_FILE, "r") as file:
        reader = csv.reader(file)
        for i, row in enumerate(reader, start=1):
            if not row:
                continue
            try:
                decrypted = decrypt_data(row[0].strip(), key)

                # === Filtering logic ===
                if role == "patient":
                    # match patientusername (added in encrypt.py)
                    if f"patientusername: {username.lower()}" not in decrypted.lower():
                        continue  # skip records not belonging to this patient

                if search_mode and search_query:
                    text = decrypted.lower()
                    if search_mode == "name" and search_query not in text:
                        continue
                    if search_mode == "disease" and search_query not in text:
                        continue

                # === Integrity Check ===
                if len(row) > 1:
                    stored_hash = row[1].strip()
                    current_hash = get_hash(decrypted)
                    if stored_hash == current_hash:
                        print(f"\nRecord {i}: {decrypted} ✅ (Integrity Verified)")
                    else:
                        print(f"\nRecord {i}: {decrypted} ⚠️ (Integrity FAILED)")
                else:
                    print(f"\nRecord {i}: {decrypted} ⚠️ (No hash stored)")

            except Exception as e:
                logging.error(f"Error decrypting record {i}: {str(e)}")
                print(f"\nRecord {i}: Error decrypting - {str(e)}")

    logging.info(f"{username} ({role}) viewed medical records.")
    write_entry("view_records", "success", username, role)   # ✅ Record viewing action


if __name__ == "__main__":
    main()
