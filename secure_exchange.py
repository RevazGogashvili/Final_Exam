import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            data = f.read(65536)  # Read in chunks
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()


def run_secure_exchange():
    print("--- Starting Secure File Exchange (RSA + AES + Hashing) ---")


    print("\n[Step 1] Generating Bob's RSA Keys...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open("private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("Saved 'private.pem' and 'public.pem'.")


    print("\n[Step 2] Alice creating plaintext message...")
    message_content = "This is a confidential file sent from Alice to Bob."
    with open("alice_message.txt", "w") as f:
        f.write(message_content)
    print("Saved 'alice_message.txt'.")


    print("\n[Step 3 & 4] Alice generating AES data and encrypting file...")

    aes_key = os.urandom(32)
    iv = os.urandom(16)

    with open("alice_message.txt", "rb") as f:
        plaintext = f.read()

    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open("encrypted_file.bin", "wb") as f:
        f.write(iv + ciphertext)
    print("Saved 'encrypted_file.bin' (IV + Ciphertext).")


    print("\n[Step 5] Alice encrypting AES key with Bob's Public Key...")
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open("aes_key_encrypted.bin", "wb") as f:
        f.write(encrypted_aes_key)
    print("Saved 'aes_key_encrypted.bin'.")


    print("\n[Step 6] Bob decrypting AES key with Private Key...")

    with open("aes_key_encrypted.bin", "rb") as f:
        enc_key_data = f.read()

    decrypted_aes_key = private_key.decrypt(
        enc_key_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("Bob successfully recovered the AES key.")


    print("\n[Step 7] Bob decrypting the file content...")

    with open("encrypted_file.bin", "rb") as f:
        file_data = f.read()

    extracted_iv = file_data[:16]
    actual_ciphertext = file_data[16:]

    cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(extracted_iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    with open("decrypted_message.txt", "w") as f:
        f.write(plaintext.decode())
    print("Saved 'decrypted_message.txt'.")

    print("\n[Step 8] Verifying Integrity...")

    original_hash = calculate_hash("alice_message.txt")
    decrypted_hash = calculate_hash("decrypted_message.txt")

    print(f"Original Hash:  {original_hash}")
    print(f"Decrypted Hash: {decrypted_hash}")

    if original_hash == decrypted_hash:
        print("\nSUCCESS: Integrity Verified. Hashes Match.")
    else:
        print("\nFAIL: Hashes do not match!")


if __name__ == "__main__":
    run_secure_exchange()