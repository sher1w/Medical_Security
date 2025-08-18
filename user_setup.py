import json
import bcrypt
import os
import re   # ✅ for password policy checks

USERS_FILE = "users.json"

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def password_is_strong(password):
    """
    ✅ Password Policy:
    - At least 8 characters
    - At least one uppercase
    - At least one lowercase
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must include at least one digit."
    if not re.search(r"[@$!%*?&#]", password):
        return False, "Password must include at least one special character (@, $, !, %, *, ?, &, #)."
    return True, "Password is strong."

def create_user():
    users = load_users()
    username = input("Enter new username: ")
    if username in users:
        print("User already exists.")
        return
    
    # ✅ enforce password policy
    while True:
        password = input("Enter password: ")
        valid, message = password_is_strong(password)
        if valid:
            break
        else:
            print("❌ Weak password:", message)

    role = input("Enter role (doctor/patient/receptionist/admin): ").lower()

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    users[username] = {
        "password": hashed.decode(),
        "role": role,
        "last_login": "Never",
        "failed_attempts": 0,   # ✅ for lockout tracking
        "locked": False         # ✅ for lockout tracking
    }

    save_users(users)
    print(f"✅ User '{username}' with role '{role}' added.")

if __name__ == "__main__":
    create_user()
