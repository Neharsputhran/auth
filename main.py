from cryptography.fernet import Fernet
import pyotp
import re
import cv2
from pyzbar.pyzbar import decode
from PIL import Image
import random
import string
import secrets  # Import for more secure random number generation

# Function to generate a key (this should be done once and stored securely)
def generate_key():
    key = Fernet.generate_key()  # Generates a valid Fernet key
    print(f"Save this key for future use: {key.decode()}")
    return key

# Function to encrypt the QR code data (URL)
def encrypt_data(data, key):
    fernet = Fernet(key)  # Create Fernet object with the correct key
    encrypted = fernet.encrypt(data.encode())  # Encrypt the data
    return encrypted

# Function to decrypt the encrypted data
def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data).decode()  # Decrypt the data
    return decrypted

# Function to scan the QR code and get the URL data
def scan_qr_code():
    # Open the webcam
    cap = cv2.VideoCapture(0)
    while True:
        ret, frame = cap.read()
        gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        decoded_objects = decode(Image.fromarray(gray_frame))

        for obj in decoded_objects:
            qr_data = obj.data.decode('utf-8')
            print("QR Code detected:", qr_data)
            cap.release()
            cv2.destroyAllWindows()
            return qr_data

        cv2.imshow("QR Code Scanner", frame)

        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()

# Function to extract the secret from the otpauth URL
def extract_secret(qr_data):
    match = re.search(r'secret=([A-Z2-7]+)', qr_data)
    if match:
        return match.group(1)
    else:
        raise ValueError("Secret not found in QR code data")

# Function to generate a numeric OTP using pyotp and the extracted secret (TOTP-based)
def generate_numeric_otp(secret):
    totp = pyotp.TOTP(secret)
    otp = totp.now()
    print("Generated Numeric OTP (Standard):", otp)
    return otp

# Function to generate an alphanumeric OTP
def generate_alphanumeric_otp(length=6):
    characters = string.ascii_letters + string.digits
    otp = ''.join(secrets.choice(characters) for i in range(length))
    return otp

if __name__ == "__main__":
    # Step 1: Scan the QR code and get the URL data
    qr_data = scan_qr_code()

    # Step 2: Generate or use a saved key (you should save this key securely)
    key = generate_key()  # Generate a new key

    # Step 3: Encrypt the QR code URL data
    encrypted_data = encrypt_data(qr_data, key)
    print("Encrypted URL:", encrypted_data)

    # Step 4: Decrypt the encrypted data (just to show decryption works)
    decrypted_data = decrypt_data(encrypted_data, key)
    print("Decrypted URL:", decrypted_data)

    # Step 5: Extract the secret key from the decrypted URL
    secret_key = extract_secret(decrypted_data)

    # Step 6: Generate a numeric OTP using the secret key (TOTP-based for compatibility)
    numeric_otp = generate_numeric_otp(secret_key)

    # Step 7: Generate an alphanumeric OTP (for custom purposes)
    alphanumeric_otp = generate_alphanumeric_otp(6)  # Generates 6-character alphanumeric OTP

    # Print the OTPs
    print("Numeric OTP:", numeric_otp)
    print("Alphanumeric OTP:", alphanumeric_otp)
