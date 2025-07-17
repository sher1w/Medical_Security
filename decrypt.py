from cryptography.fernet import Fernet
import csv

username = input("Enter user name : ")
password = input("Enter password :")

users = {
    "dr123": ["passdoc", "doctor"],
    "recep01": ["passrec", "receptionist"]
}


if username not in users:
    print(" User name does not exist ")
    exit()
WORD_PASS = users[username][0]

for i in range(2):
    if password == WORD_PASS:
        print("Logged in Successfully.")
        break 
    elif password  != WORD_PASS: 
        print("Wrong Passwords  entered .")
    print(f"Try {i + 1}")
    password = input("Enter password :")
    if i == 3:
        exit()


role = users[username][1]
print("Logged in as: ", role)

def load_key():
    return open("secret.key", "rb").read()

def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    return f.decrypt(encrypted_data.encode()).decode()


with open("medical_data.csv","r") as file:
    reader =csv.reader(file)
    header = next(reader,None)
    for row in reader:
        if row:
            enc_data = row[0]
            break



key = load_key()
dencrypted = decrypt_data(enc_data.strip(), key)

print(dencrypted)
