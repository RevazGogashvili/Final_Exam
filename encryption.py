import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def run_lab():
    print("--- Starting Encrypted Messaging Lab ---")


    print("\n[User A] Generating RSA Key Pair...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()
    print("[User A] Public Key shared.")


    print("\n[User B] Preparing to encrypt message...")

    original_message = "This is a top secret message."

    with open("message.txt", "w") as f:
        f.write(original_message)

    aes_key = os.urandom(32)
    print("[User B] Generated AES-256 Key.")

    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(original_message.encode()) + encryptor.finalize()

    tag = encryptor.tag

    with open("encrypted_message.bin", "wb") as f:
        f.write(nonce + tag + ciphertext)
    print("[User B] Message encrypted and saved to 'encrypted_message.bin'.")

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
    print("[User B] AES key encrypted with RSA and saved to 'aes_key_encrypted.bin'.")


    print("\n[User A] Received files. Decrypting...")

    with open("aes_key_encrypted.bin", "rb") as f:
        loaded_enc_aes_key = f.read()

    decrypted_aes_key = private_key.decrypt(
        loaded_enc_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("[User A] AES Key successfully decrypted.")

    with open("encrypted_message.bin", "rb") as f:
        data = f.read()

    loaded_nonce = data[:12]
    loaded_tag = data[12:28]
    loaded_ciphertext = data[28:]

    cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.GCM(loaded_nonce, loaded_tag))
    decryptor = cipher.decryptor()

    decrypted_message_bytes = decryptor.update(loaded_ciphertext) + decryptor.finalize()
    decrypted_message = decrypted_message_bytes.decode()

    with open("decrypted_message.txt", "w") as f:
        f.write(decrypted_message)

    print(f"[User A] Message Decrypted: '{decrypted_message}'")
    print("[User A] Saved to 'decrypted_message.txt'.")


if __name__ == "__main__":
    run_lab()