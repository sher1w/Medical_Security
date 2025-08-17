import json
import bcrypt
import os

USERS_FILE = "users.json"

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def create_user():
    users = load_users()
    username = input("Enter new username: ")
    if username in users:
        print("User already exists.")
        return
    password = input("Enter password: ")
    role = input("Enter role (doctor/patient/receptionist/admin): ").lower()

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    users[username] = {
        "password": hashed.decode(),
        "role": role,
        "last_login": "Never",
        "failed_attempts": 0,   # ✅ added for lockout tracking
        "locked": False         # ✅ added for lockout tracking
    }

    save_users(users)
    print(f"User '{username}' with role '{role}' added.")

if __name__ == "__main__":
    create_user()
