import json, getpass, os
import bcrypt

USERS_FILE = "users.json"
LOG_FILE = "access.log"

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
    password = getpass.getpass("Password: ")
    hashed = users[username]["password"].encode()

    if bcrypt.checkpw(password.encode(), hashed):
        role = users[username]["role"]
        if role != "admin":
            print("Access denied. Only admin can view logs.")
            return None
        print("Admin login successful.")
        return username
    else:
        print("Incorrect password.")
        return None

def main():
    print("=== View Access Logs ===")
    user = login()
    if not user:
        return

    if not os.path.exists(LOG_FILE):
        print("No logs available.")
        return

    print("\n--- Access Log Entries ---")
    with open(LOG_FILE, "r") as f:
        for line in f:
            print(line.strip())

if __name__ == "__main__":
    main()
