import os
import cv2
import numpy as np
from pyzbar.pyzbar import decode
from PIL import Image
import urllib.parse
import pyotp


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


image = input('image > ')

qrstring = capture_and_decode(image)

secret = extract_secret(qrstring)

totp = pyotp.TOTP(secret)

print(f"Your OTP is: {totp.now()}")
