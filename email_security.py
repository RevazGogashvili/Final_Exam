import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def generate_key_pair(filename_prefix):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    priv_filename = f"{filename_prefix}_private.key"
    with open(priv_filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    pub_filename = f"{filename_prefix}_public.asc"
    with open(pub_filename, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key, public_key


def run_email_simulation():
    print("--- PGP/S/MIME Email Security Simulation ---")


    print("\n[Step 1] Generating Keys...")
    alice_private, alice_public = generate_key_pair("alice")
    bob_private, bob_public = generate_key_pair(
        "bob")

    os.replace("bob_public.asc", "public.asc")
    os.replace("bob_private.key", "private.key")
    print("Keys generated. Saved Bob's keys as 'public.asc' and 'private.key'.")


    print("\n[Step 2] Alice composing message...")
    message = "Confidential: The Q3 financial report is attached. Verification required."
    with open("original_message.txt", "w") as f:
        f.write(message)
    message_bytes = message.encode('utf-8')


    print("[Step 3] Alice signing the message (Integrity & Non-Repudiation)...")
    signature = alice_private.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("[Step 4] Alice encrypting message and signature (Confidentiality)...")

    combined_data = signature + message_bytes

    session_key = os.urandom(32)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(combined_data) + encryptor.finalize()

    encrypted_session_key = bob_public.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    payload = encrypted_session_key + iv + ciphertext
    with open("signed_message.asc", "wb") as f:
        f.write(base64.b64encode(payload))
    print("Encrypted email package saved to 'signed_message.asc'.")

    print("\n[Step 5] Bob receiving and decrypting...")

    with open("signed_message.asc", "rb") as f:
        encoded_payload = f.read()
    payload = base64.b64decode(encoded_payload)

    enc_session_key = payload[:256]
    loaded_iv = payload[256:272]
    loaded_ciphertext = payload[272:]

    decrypted_session_key = bob_private.decrypt(
        enc_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(decrypted_session_key), modes.CFB(loaded_iv))
    decryptor = cipher.decryptor()
    decrypted_combined = decryptor.update(loaded_ciphertext) + decryptor.finalize()

    extracted_signature = decrypted_combined[:256]
    extracted_message_bytes = decrypted_combined[256:]

    with open("decrypted_message.txt", "w") as f:
        f.write(extracted_message_bytes.decode('utf-8'))
    print("Message decrypted and saved to 'decrypted_message.txt'.")

    print("[Step 6] Bob verifying the digital signature...")

    try:
        alice_public.verify(
            extracted_signature,
            extracted_message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("\nSUCCESS: Signature is VALID.")
        print(" - The message definitely came from Alice.")
        print(" - The message was not altered in transit.")
    except Exception as e:
        print("\nERROR: Signature is INVALID! Message may be tampered or sender is fake.")


if __name__ == "__main__":
    run_email_simulation()