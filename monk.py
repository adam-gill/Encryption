import os
import os.path
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# my key = b'KCeG-7jM4fe5gIgyrG6imwNpePqadM5Gp1Qx-yI4r3E='

# test key = b'cVWo8Y3KwhfZy6XTF9tMGARIzNrCRnWbzF6H0yKv0as='


if not os.path.exists('out.txt'):
    file = open('out.txt', 'wb')
    file.close()



def key_check(value: str) -> str:
    value = value.encode()
    salt = b'9\xb5s\x06%&\x0b7\x96\xbc\x1c\r\xff\x80\xf6\x8c'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=500000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(value))


def dec(value: str) -> str:
    f = Fernet(masterkey)
    return f.decrypt(value)

def encfile(fname: str): 
  with open(fname, "rb") as thefile:
    contents = thefile.read()
    contents_encrypted = Fernet(masterkey).encrypt(contents)
  with open(fname, "wb") as thefile:
    thefile.write(contents_encrypted)

def decfile(fname: str):
  with open(fname, "rb") as thefile:
    contents = thefile.read()
    contents_decrypted = Fernet(masterkey).decrypt(contents)
  
  with open(fname, "wb") as thefile:
    thefile.write(contents_decrypted)


masterkey = key_check(input("Enter your key: \n"))

while True:
    choice = input("1 for encryption, 2 for decryption, and 'quit' to quit:\n")
    if choice == "1":
        choice = input("1 to encrypt custom text or 2 to encrypt text file:\n")
        if choice == "1":
            choice = input("Enter text to encrypt:\n")
            with open("out.txt", "w") as thefile:
                thefile.write(choice)
            encfile("out.txt")
            with open("out.txt", "r") as thefile:
                print()
                print("Encrypted text: " + str(thefile.read()))
                print()
            print()
        if choice == "2":
            encfile("out.txt")
            with open("out.txt", "r") as thefile:
                print()
                print("Encrypted text: " + str(thefile.read()))
                print()
    elif choice == "2":
        choice = input("1 to decrypt custom text or 2 to decrypt textfile:\n")
        if choice == "1":
            choice = input("Enter text for decryption:\n")
            choice.encode()
            print()
            print("Decrypted text: " + str(Fernet(masterkey).decrypt(choice), 'utf-8'))
            print()
        elif choice == "2":
            decfile("out.txt")
            with open("out.txt", "r") as thefile:
                print()
                print("Decrypted text: " + str(thefile.read()))
                print()
    elif choice == "quit":
        break
    else:
        print("Error")



