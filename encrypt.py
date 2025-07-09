from cryptography.fernet import Fernet
import csv

def write_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("secret.key", "rb").read()

def encrypt_data(data, key):
    f = Fernet(key)
    return f.encrypt(data.encode())

try:
    open("secret.key", "rb")
except  FileNotFoundError:
    write_key()


key = load_key()

patient_name =input("Enter the name please: ")
patient_disease = input("Enter the disease please: ")
patient_pres = input("Enter the Prescreption Please: ")

patient_data = f"Name: {patient_name}, Disease:{patient_disease}, Prescription:{patient_pres} "
 
encrypted = encrypt_data(patient_data, key)

with open("medical_data.csv","w",newline='') as file:
    writer =csv.writer(file)
    writer.writerow(["EncryptedDATA"])
    writer.writerow([encrypted.decode()])
print("Done.")
