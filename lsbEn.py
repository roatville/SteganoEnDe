from PIL import Image
import numpy as np
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import zipfile


def encrypt_data(data, password):
    # Generate a random salt
    salt = os.urandom(16)
    # Generate a random IV
    iv = os.urandom(16)

    # Derive the same key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10000
    )
    key = kdf.derive(password.encode())

    # AES encryption
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    # Return the concatenated salt, IV, and encrypted data
    return salt + iv + encrypted_data


def embed_in_image(image_path, encrypted_data, output_path):
    img = Image.open(image_path)
    img = img.convert('RGB')
    pixels = np.array(img)

    data_bits = ''.join(format(byte, '08b') for byte in encrypted_data)

    data_index = 0
    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            for k in range(3):  # For R, G, B channels
                if data_index < len(data_bits):
                    # Embed the bit in the LSB
                    pixels[i][j][k] = (pixels[i][j][k] & ~1) | int(data_bits[data_index])
                    data_index += 1

    # Save the modified image
    modified_img = Image.fromarray(pixels)
    modified_img.save(output_path)


def create_zip_file(file_list):
    with zipfile.ZipFile('encrypted_data.zip', 'w') as zipf:
        for file in file_list:
            zipf.write(file)


def main():
    # List of files to be zipped and encrypted
    files = ['file1.txt', 'file2.txt']  # Replace with your file names
    create_zip_file(files)

    # Read the zip file
    with open('encrypted_data.zip', 'rb') as f:
        zip_data = f.read()

    password = 'your_secure_password'
    encrypted_data = encrypt_data(zip_data, password)

    # Embed in image
    embed_in_image('input_image.jpg', encrypted_data, 'output_image.png')

    print('Encryption and embedding complete.')


if __name__ == "__main__":
    main()
