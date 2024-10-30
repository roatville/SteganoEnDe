from PIL import Image
import numpy as np
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


def extract_from_lsb(image):
    img = Image.open(image)
    img = img.convert('RGB')
    pixels = np.array(img)

    data_bits = ''
    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            for k in range(3):  # For R, G, B channels
                data_bits += str(pixels[i][j][k] & 1)  # Get the LSB
    return data_bits


def decrypt_data(encrypted_data, password):
    encrypted_data_bytes = bytearray(encrypted_data)

    # Extract salt, IV, and actual encrypted data
    salt = bytes(encrypted_data_bytes[:16])
    iv = bytes(encrypted_data_bytes[16:32])
    actual_encrypted_data = bytes(encrypted_data_bytes[32:])

    # Derive the same key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # AES decryption
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(actual_encrypted_data) + decryptor.finalize()

    return decrypted_data


def main():
    # The input image with embedded data
    stego_image_path = 'output_image.png'  # Ensure this matches the output of the encryption
    password = 'your_secure_password'

    # Extract data bits from the image
    data_bits = extract_from_lsb(stego_image_path)

    # Convert binary data back to bytes
    encrypted_data = bytearray()
    for i in range(0, len(data_bits), 8):
        byte = data_bits[i:i + 8]
        encrypted_data.append(int(byte, 2))

    # Decrypt the extracted data
    decrypted_zip_data = decrypt_data(encrypted_data, password)

    # Save the decrypted data
    with open('decrypted_data.zip', 'wb') as f:
        f.write(decrypted_zip_data)

    print('Decryption complete. Decrypted data saved as decrypted_data.zip.')


if __name__ == "__main__":
    main()
