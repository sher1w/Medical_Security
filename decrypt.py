from cryptography.fernet import Fernet
import csv

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
