import os
from cryptography.fernet import Fernet

KEY_FILE = "security_key.key"

# Generate encryption key if not exists
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())

with open(KEY_FILE, "rb") as f:
    KEY = f.read()

fernet = Fernet(KEY)


def encrypt_file(file_path):
    """Encrypt a file and return encrypted file path."""
    with open(file_path, "rb") as f:
        data = f.read()

    encrypted_data = fernet.encrypt(data)

    enc_path = file_path + ".enc"
    with open(enc_path, "wb") as ef:
        ef.write(encrypted_data)

    # Optional: remove original
    os.remove(file_path)

    return enc_path


def decrypt_file(enc_path, output_path=None):
    """Decrypt a file and return decrypted file path."""
    with open(enc_path, "rb") as ef:
        encrypted_data = ef.read()

    decrypted_data = fernet.decrypt(encrypted_data)

    if not output_path:
        output_path = enc_path.replace(".enc", "_decrypted")

    with open(output_path, "wb") as df:
        df.write(decrypted_data)

    return output_path
