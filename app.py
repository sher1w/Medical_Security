# app.py
import streamlit as st
import os, json, csv, hashlib
import bcrypt
from cryptography.fernet import Fernet
from datetime import datetime

# ---- Config ----
USERS_FILE = "users.json"
CSV_FILE = "medical_data.csv"
KEY_FILE = "secret.key"

# ---- Helpers ----
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def write_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)

def load_key():
    if not os.path.exists(KEY_FILE):
        write_key()
    with open(KEY_FILE, "rb") as f:
        return f.read()

def encrypt_data(plaintext: str, key: bytes) -> str:
    return Fernet(key).encrypt(plaintext.encode()).decode()

def decrypt_data(ciphertext: str, key: bytes) -> str:
    return Fernet(key).decrypt(ciphertext.encode()).decode()

def get_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def check_login(username: str, password: str):
    users = load_users()
    if username in users:
        hashed = users[username]["password"].encode()
        if bcrypt.checkpw(password.encode(), hashed):
            return username, users[username]["role"]
    return None, None

# ---- Streamlit UI setup ----
st.set_page_config(page_title="Medical Security System", layout="wide")
st.title("🔐 Medical Security System")
st.caption("A demo: encrypted medical records with RBAC, hashing and patient account mapping.")

# init session state
if "auth_user" not in st.session_state:
    st.session_state.auth_user = None
    st.session_state.auth_role = None

# ---- Sidebar: Login / Register ----
with st.sidebar:
    st.header("Session")
    if st.session_state.auth_user:
        st.success(f"Logged in as {st.session_state.auth_user} ({st.session_state.auth_role})")
        if st.button("Logout"):
            st.session_state.auth_user = None
            st.session_state.auth_role = None
            st.rerun()
    else:
        action = st.radio("Action", ["Login", "Register"], index=0)
        if action == "Login":
            in_user = st.text_input("Username", key="login_user")
            in_pw = st.text_input("Password", type="password", key="login_pw")
            if st.button("Login"):
                user, role = check_login(in_user, in_pw)
                if user:
                    st.session_state.auth_user = user
                    st.session_state.auth_role = role
                    st.success("Login successful")
                    st.rerun()
                else:
                    st.error("Invalid credentials")
        else:
            # Register (self-register only as patient)
            reg_user = st.text_input("Choose username", key="reg_user")
            reg_pw = st.text_input("Choose password", type="password", key="reg_pw")
            if st.button("Register"):
                if not reg_user or not reg_pw:
                    st.error("Both username and password required.")
                else:
                    users = load_users()
                    if reg_user in users:
                        st.error("Username already exists.")
                    else:
                        hashed = bcrypt.hashpw(reg_pw.encode(), bcrypt.gensalt()).decode()
                        users[reg_user] = {
                            "password": hashed,
                            "role": "patient",
                            "last_login": "Never",
                            "failed_attempts": 0,
                            "locked": False
                        }
                        save_users(users)
                        st.success("Account created. You can now log in.")

# If not logged in, stop and show prompt
if not st.session_state.auth_user:
    st.info("Please login or register (sidebar) to continue.")
    st.stop()

# ---- Main area (logged in) ----
user = st.session_state.auth_user
role = st.session_state.auth_role

# Menu choices
menu_items = ["Encrypt Record", "View Records"]
if role == "admin":
    menu_items.insert(1, "User Management")
choice = st.selectbox("Choose Action", menu_items)

# ----- ENCRYPT RECORD -----
if choice == "Encrypt Record":
    st.header("➕ Add Encrypted Medical Record")

    if role not in ["doctor", "receptionist", "admin"]:
        st.error("You are not authorized to add records.")
    else:
        users = load_users()
        patient_accounts = [u for u, v in users.items() if v.get("role") == "patient"]
        st.write("Select an existing patient account or create a new patient account for this record.")
        option = st.radio("Patient option", ["Select existing patient account", "Create new patient account"])

        patient_username = None
        patient_display_name = ""
        if option.startswith("Select") and patient_accounts:
            patient_username = st.selectbox("Patient account", ["--choose--"] + patient_accounts)
            if patient_username == "--choose--":
                patient_username = None
            patient_display_name = st.text_input("Patient display name (optional)", value="")
        else:
            # create new patient
            new_p_username = st.text_input("New patient username (no spaces)")
            new_p_pw = st.text_input("New patient password", type="password")
            patient_display_name = st.text_input("Patient full name (for record)", value="")
            if st.button("Create patient account"):
                if not new_p_username or not new_p_pw:
                    st.error("Username and password required to create patient account.")
                else:
                    users = load_users()
                    if new_p_username in users:
                        st.error("Username already exists.")
                    else:
                        hashed = bcrypt.hashpw(new_p_pw.encode(), bcrypt.gensalt()).decode()
                        users[new_p_username] = {
                            "password": hashed,
                            "role": "patient",
                            "last_login": "Never",
                            "failed_attempts": 0,
                            "locked": False
                        }
                        save_users(users)
                        st.success(f"Patient account '{new_p_username}' created.")
                        patient_username = new_p_username

        disease = st.text_input("Disease")
        prescription = st.text_area("Prescription")
        if st.button("Encrypt & Save Record"):
            if not patient_username:
                st.error("Patient username is required (select or create patient).")
            elif not disease or not prescription:
                st.error("Disease and prescription are required.")
            else:
                key = load_key()
                # Use a stable, parseable format
                pdata = f"PatientUsername: {patient_username}, PatientName: {patient_display_name}, Disease: {disease}, Prescription: {prescription}"
                encrypted = encrypt_data(pdata, key)
                h = get_hash(pdata)
                with open(CSV_FILE, "a", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([encrypted, h])
                st.success("Record saved and encrypted.")
                st.info("Patient account associated: " + patient_username)

# ----- USER MANAGEMENT (ADMIN) -----
elif choice == "User Management":
    st.header("👤 User Management (Admin)")
    if role != "admin":
        st.error("Only admins can manage users.")
    else:
        with st.form("create_user_form"):
            new_user = st.text_input("New username")
            new_pw = st.text_input("New password", type="password")
            new_role = st.selectbox("Role", ["doctor", "patient", "receptionist", "admin"])
            submitted = st.form_submit_button("Create user")
        if submitted:
            if not new_user or not new_pw:
                st.error("Username and password required.")
            else:
                users = load_users()
                if new_user in users:
                    st.error("User already exists.")
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
                    st.success(f"User '{new_user}' created with role '{new_role}'.")

        st.markdown("---")
        st.caption("Existing users (safe view):")
        users = load_users()
        safe_view = {u: {"role": v["role"]} for u, v in users.items()}
        st.json(safe_view)

# ----- VIEW RECORDS (Decrypt) -----
elif choice == "View Records":
    st.header("📂 View Medical Records")
    if not os.path.exists(CSV_FILE):
        st.info("No medical records found.")
    else:
        key = load_key()

        search_query = ""
        search_by = None
        if role in ["doctor", "admin"]:
            search_mode = st.radio("Display mode", ["View All", "Search"])
            if search_mode == "Search":
                search_by = st.selectbox("Search by", ["name", "disease"])
                search_query = st.text_input("Enter search term").lower()

        shown = False
        with open(CSV_FILE, "r") as f:
            reader = csv.reader(f)
            for idx, row in enumerate(reader, start=1):
                if not row:
                    continue
                try:
                    ciphertext = row[0].strip()
                    decrypted = decrypt_data(ciphertext, key)
                except Exception as e:
                    st.error(f"Error decrypting record {idx}: {str(e)}")
                    continue

                # Integrity
                integrity = "No hash"
                if len(row) > 1:
                    stored = row[1].strip()
                    integrity = "OK" if stored == get_hash(decrypted) else "FAILED"

                # Filter by patient role
                if role == "patient":
                    if f"patientusername: {user.lower()}" not in decrypted.lower():
                        continue

                # Search filters for doctors/admins
                if search_by and search_query:
                    text = decrypted.lower()
                    if search_by == "name" and search_query not in text:
                        continue
                    if search_by == "disease" and search_query not in text:
                        continue

                # Show record
                st.write(f"**Record {idx}:** {decrypted}  —  Integrity: **{integrity}**")
                shown = True

        if not shown:
            st.info("No matching records to display.")
