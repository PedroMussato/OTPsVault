import os
import cv2
import numpy as np
from pyzbar.pyzbar import decode
from PIL import Image
import urllib.parse
import pyotp
import getpass
import hashlib
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
import base64

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    # Generate a key from a password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_path: str, password: str) -> None:
    # Encrypt a file with a password
    salt = os.urandom(16)  # Generate a new salt
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)

    with open(file_path, 'rb') as file:
        data = file.read()

    encrypted_data = fernet.encrypt(data)

    with open(file_path + ".enc", 'wb') as file:
        file.write(salt + encrypted_data)  # Save salt and encrypted data together

def decrypt_file(encrypted_file_path: str, password: str, output_file_path: str) -> None:
    # Decrypt a file with a password
    with open(encrypted_file_path, 'rb') as file:
        salt = file.read(16)  # Extract salt
        encrypted_data = file.read()  # Read the encrypted data

    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)

    with open(output_file_path, 'wb') as file:
        file.write(decrypted_data)
        
def sha256hash(content):
    # Create a SHA-256 hash object
    sha256_hash = hashlib.sha256()
    # Update the hash object with the bytes of the data
    sha256_hash.update(content.encode('utf-8'))
    # Get the hexadecimal representation of the hash
    hash_result = sha256_hash.hexdigest()
    return hash_result


def capture_and_decode(image):
    # Carrega a imagem e converte para um array numpy
    img = Image.open(image)
    img_np = np.array(img)
    
    # Decodifica o QR code
    qr_codes = decode(img_np)
    for qr_code in qr_codes:
        data = qr_code.data.decode("utf-8")
        return data

def extract_secret(qr_data):
    # Parse the URL
    parsed_url = urllib.parse.urlparse(qr_data)

    # Extract the path and query
    path = parsed_url.path
    query = parsed_url.query

    # Decode the path and split by ':' to get the base and user info
    path_parts = path.split(':')

    # Create a dictionary for the parsed result
    result = {
        'scheme': parsed_url.scheme,
        'path': path_parts,
    }

    # Parse the query parameters into a dictionary
    query_params = urllib.parse.parse_qs(query)

    # Add the query parameters to the result dictionary
    result['params'] = {k: v[0] for k, v in query_params.items()}  # Get the first value for each key

    # Corrected return statement
    return result['params']['secret']


menu = \
"""
1 - read a otp
2 - record a otp
0 - exit
"""

# get password
if os.path.exists('.secret') and (os.path.exists('.data') or os.path.exists('.data.enc')):
    while True:
        password = getpass.getpass('type your password to unlock otp vault > ')
        current_password_hash = sha256hash(password)
        with open('.secret', 'r') as secret_file:
            stored_password_hash = secret_file.read()
        if not stored_password_hash == current_password_hash:
            print('password not match, please enter again')
        else:
            break

# if no database create a new database and password
else:
    while True:
        print('create a new otp database')
        password = getpass.getpass('type the password > ')
        password1 = getpass.getpass('type the password again > ')
        if password == password1:
            with open('.secret', 'w') as secret_file:
                secret_file.write(sha256hash(password))   
            with open('.data', 'w') as data_file:
                data_file.write('')
        else:
            print('password not match')    

while True:
    print(menu)

    # allow user to select option
    r = input('> ')
    if r == '0':
        break
    elif r == '1': # if read otp
        decrypt_file('.data.enc', password, '.data')
        
        with open('.data', 'r') as data_file:
            otps = json.loads(data_file.read())
        
        encrypt_file('.data',password)
        
        os.remove('.data')
        
        while True:
            for k in otps.keys():
                print(k)
        
            r = input('select the otp > ')
            if r in otps.keys():
                break
            else:
                print('otp not found, select again')
        
        totp = pyotp.TOTP(otps[r])
        print(f"Your OTP is: {totp.now()}")


    elif r == '2': # if record otp
        otps = dict()

        while True:
            otpname = input('OTP name > ')
            r = input(f'the OTP name will be {otpname}, are you sure? [y/n] > ')
            if r.lower() == 'y':
                break

        while True:
            otpqrcodepath = input('qrcode image path > ')
            if os.path.exists(otpqrcodepath):
                break
            else:
                print('image not found')
        
        qrstring = capture_and_decode(otpqrcodepath)        
        secret = extract_secret(qrstring)

        otps[otpname] = secret

        with open('.data', 'w') as data_file:
            data_file.write(json.dumps(otps))

        encrypt_file('.data',password)

        os.remove('.data')