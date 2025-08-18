import streamlit as st
import json, bcrypt, os, csv, hashlib
from cryptography.fernet import Fernet
from datetime import datetime

# === Constants ===
USERS_FILE = "users.json"
KEY_FILE = "secret.key"
CSV_FILE = "medical_data.csv"


# === Helpers ===
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)


def check_login(username, password):
    users = load_users()
    if username in users:
        hashed = users[username]["password"].encode()
        if bcrypt.checkpw(password.encode(), hashed):
            return username, users[username]["role"]
    return None, None


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


def decrypt_data(data, key):
    return Fernet(key).decrypt(data.encode()).decode()


def get_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()


# === Streamlit UI ===
st.set_page_config(page_title="Medical Security System", page_icon="🔒", layout="wide")
st.title("🔒 Medical Security System")
st.caption("A secure platform for managing and viewing encrypted medical records.")


# === Sidebar (Login / Register) ===
if "auth_user" not in st.session_state:
    st.session_state.auth_user = None
    st.session_state.auth_role = None

with st.sidebar:
    st.header("Session")
    if st.session_state.auth_user:
        st.success(f"Logged in as {st.session_state.auth_user} ({st.session_state.auth_role})")
        if st.button("Logout"):
            st.session_state.auth_user = None
            st.session_state.auth_role = None
            st.rerun()
    else:
        option = st.radio("Choose Action", ["Login", "Register"])

        if option == "Login":
            lu = st.text_input("Username")
            lp = st.text_input("Password", type="password")
            if st.button("Login"):
                user, role = check_login(lu, lp)
                if user:
                    st.session_state.auth_user = user
                    st.session_state.auth_role = role
                    st.success("✅ Login successful")
                    st.rerun()
                else:
                    st.error("Invalid credentials.")

        elif option == "Register":
            new_user = st.text_input("Choose Username")
            new_pw = st.text_input("Choose Password", type="password")
            if st.button("Register"):
                users = load_users()
                if new_user in users:
                    st.error("Username already exists.")
                elif not new_user or not new_pw:
                    st.error("All fields are required.")
                else:
                    hashed = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
                    users[new_user] = {
                        "password": hashed,
                        "role": "patient",   # self-registrations are always patients
                        "last_login": "Never",
                        "failed_attempts": 0,
                        "locked": False
                    }
                    save_users(users)
                    st.success("✅ Account created! You can now log in.")


# === Main Area (only if logged in) ===
if st.session_state.auth_user:
    role = st.session_state.auth_role
    choice = st.selectbox("Choose Action", ["Encrypt Record", "View Records", "User Management"])

    # --- Encrypt Medical Record ---
    if choice == "Encrypt Record":
        st.subheader("➕ Add Encrypted Medical Record")
        if role not in ["doctor", "receptionist", "admin"]:
            st.error("You are not authorized to add records.")
        else:
            name = st.text_input("Patient Name")
            disease = st.text_input("Disease")
            prescription = st.text_area("Prescription")
            if st.button("Encrypt & Save Record"):
                if name and disease and prescription:
                    data = f"Name: {name}, Disease: {disease}, Prescription: {prescription}, PatientUsername: {name.lower()}"
                    key = load_key()
                    encrypted = encrypt_data(data, key)
                    hash_val = get_hash(data)

                    with open(CSV_FILE, "a", newline="") as file:
                        writer = csv.writer(file)
                        writer.writerow([encrypted, hash_val])

                    st.success("✅ Encrypted medical data saved.")
                else:
                    st.error("All fields are required.")

    # --- View Medical Records ---
    elif choice == "View Records":
        st.subheader("📂 View Medical Records")
        key = load_key()

        search_mode = None
        search_query = None
        if role in ["doctor", "admin"]:
            choice2 = st.radio("Do you want to:", ["View All", "Search"])
            if choice2 == "Search":
                search_mode = st.selectbox("Search by:", ["name", "disease"])
                search_query = st.text_input("Enter search term").lower()

        if os.path.exists(CSV_FILE):
            with open(CSV_FILE, "r") as file:
                reader = csv.reader(file)
                for i, row in enumerate(reader, start=1):
                    if not row:
                        continue
                    try:
                        decrypted = decrypt_data(row[0].strip(), key)

                        if role == "patient" and f"patientusername: {st.session_state.auth_user.lower()}" not in decrypted.lower():
                            continue

                        if search_mode and search_query:
                            text = decrypted.lower()
                            if search_mode == "name" and search_query not in text:
                                continue
                            if search_mode == "disease" and search_query not in text:
                                continue

                        if len(row) > 1:
                            stored_hash = row[1].strip()
                            current_hash = get_hash(decrypted)
                            integrity = "✅ Integrity Verified" if stored_hash == current_hash else "⚠️ Integrity FAILED"
                        else:
                            integrity = "⚠️ No hash stored"

                        st.write(f"**Record {i}:** {decrypted} ({integrity})")

                    except Exception as e:
                        st.error(f"Error decrypting record {i}: {str(e)}")
        else:
            st.warning("No medical records found.")

    # --- User Management (Admin Only) ---
    elif choice == "User Management":
        st.subheader("👤 User Management (Admin)")
        if role != "admin":
            st.error("Access denied. Only admins can manage users.")
        else:
            new_user = st.text_input("New Username")
            new_pw = st.text_input("New Password", type="password")
            new_role = st.selectbox("Role", ["doctor", "patient", "receptionist", "admin"])
            if st.button("Create User"):
                users = load_users()
                if new_user in users:
                    st.error("User already exists.")
                elif not new_user or not new_pw:
                    st.error("All fields required.")
                else:
                    hashed = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
                    users[new_user] = {
                        "password": hashed,
                        "role": new_role,
                        "last_login": "Never",
                        "failed_attempts": 0,
                        "locked": False
                    }
                    save_users(users)
                    st.success(f"✅ User '{new_user}' with role '{new_role}' added.")

            st.markdown("---")
            st.caption("Existing users (safe view):")
            users = load_users()
            safe_view = {u: {"role": v["role"]} for u, v in users.items()}
            st.json(safe_view)

else:
    st.info("Please log in or register to continue.")
