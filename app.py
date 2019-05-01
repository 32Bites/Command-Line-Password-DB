import json
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from terminaltables import AsciiTable


vault_format = {"logins": [
    {"website_url": "https://google.com", "username": "username", "password": "password"},
    {"website_url": "https://example.com", "username": "username", "password": "password"}
]}

empty_vault = {"logins": []}



def createVault():
    name_of_vault = input("Name Of Vault ? ")
    vault_password = input("Password For Vault ? ").encode()

    with open("vaults/{}.vault".format(name_of_vault), "wb") as vault:
        vault_contents = json.dumps(empty_vault).encode()
        salt = b'vault_OOFYDOOFY'
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
        key = base64.urlsafe_b64encode(kdf.derive(vault_password))
        encrypter = Fernet(key)
        crypted = encrypter.encrypt(vault_contents)
        vault.write(crypted) 

def printVaultContents(password = None, name = None):
    name_of_vault = name
    vault_password = password
    if not password and not name:
        name_of_vault = input("Name Of Vault ? ")
        vault_password = input("Password For Vault ? ").encode()

    with open("vaults/{}.vault".format(name_of_vault), "rb") as vault:
        vault_contents = vault.read()
        salt = b'vault_OOFYDOOFY'
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
        key = base64.urlsafe_b64encode(kdf.derive(vault_password))
        decrypter = Fernet(key)
        crypted = decrypter.decrypt(vault_contents).decode()
        jsonData = json.loads(crypted)

        table_data = [
            ['ID', 'Website URL', 'Username', 'Password']
        ]

        for i, data in enumerate(jsonData['logins']):
            table_data.append([str(i + 1), data['website_url'], data['username'], data['password']])

        table = AsciiTable(table_data)
        print(table.table)

def addLoginToVault():
    name_of_vault = input("Name Of Vault ? ")
    vault_password = input("Vault Password ? ").encode()

    with open("vaults/{}.vault".format(name_of_vault), "rb+") as vault:
        vault_contents = vault.read()
        salt = b'vault_OOFYDOOFY'
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
        key = base64.urlsafe_b64encode(kdf.derive(vault_password))
        decrypter = Fernet(key)
        crypted = decrypter.decrypt(vault_contents).decode()
        jsonData = json.loads(crypted)

        website_url = input("Website URL ? ")
        username = input("Username ? ")
        password = input("Password ? ")
        jsonData['logins'].append({"website_url": website_url, "username": username, "password": password})

        encryptedData = decrypter.encrypt(json.dumps(jsonData).encode())
        vault.seek(0)
        vault.truncate()
        vault.write(encryptedData)
    printVaultContents(vault_password, name_of_vault)



def mainMenu():
    print("Welcome To Password Vault!")
    print("What would you like to do?")
    print("[1] Create a vault")
    print("[2] Decrypt a vault and view logins")
    print("[3] Add Login")
    print("[4] Exit")

    user_input = int(input("Choice ? "))

    if user_input == 1:
        createVault()
    elif user_input == 2:
        printVaultContents()
    elif user_input == 3:
        addLoginToVault()
    elif user_input == 4:
        exit(0)
    else:
        print("Unknown Option")



if __name__ == "__main__":
    while True:
        mainMenu()