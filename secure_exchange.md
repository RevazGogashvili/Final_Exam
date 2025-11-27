This project simulates a secure file transfer between two parties, Alice and Bob. It utilizes a **Hybrid Encryption** scheme, combining the speed of AES (Symmetric) with the secure key distribution of RSA (Asymmetric). It also implements SHA-256 hashing to verify that the file was not tampered with during transit.

#### Step-by-Step:

1.  **Key Generation (Bob):** Bob creates an RSA Key Pair. He keeps `private.pem` secret and shares `public.pem` with Alice.
2.  **Preparation (Alice):** Alice creates a file `alice_message.txt`.
3.  **Symmetric Encryption (Alice):**
    *   Alice generates a random AES-256 key and an Initialization Vector (IV).
    *   She encrypts the file using AES-CBC mode.
    *   Output: `encrypted_file.bin`.
4.  **Key Encapsulation (Alice):**
    *   Alice encrypts the AES key using Bob's RSA `public.pem`.
    *   Output: `aes_key_encrypted.bin`.
5.  **Decryption (Bob):**
    *   Bob receives the files.
    *   He uses his `private.pem` to decrypt the AES key.
    *   He uses the recovered AES key and IV to decrypt the file.
    *   Output: `decrypted_message.txt`.
6.  **Integrity Check:** Both the original and decrypted files are hashed using SHA-256. If the hashes match, the transfer is verified as secure and error-free.

## Comparison: AES vs. RSA

| Feature | AES (Advanced Encryption Standard) | RSA (Rivest–Shamir–Adleman) |
| :--- | :--- | :--- |
| **Type** | Symmetric (Same key encrypts/decrypts) | Asymmetric (Public/Private key pair) |
| **Speed** | Extremely Fast. Efficient for large data. | Slow. Computationally heavy. |
| **Key Length** | 128, 192, or 256 bits. | Typically 2048 or 4096 bits. |
| **Use Case** | Encrypting the actual data (files, HDD, streams). | Encrypting the *keys* (Key Exchange) or Digital Signatures. |
| **Security** | Secure against brute force (at 256-bit). Key distribution is the main risk. | Secure based on the difficulty of factoring large prime numbers. |

**Why use Hybrid?**

If we tried to encrypt a large 1GB video file with RSA, it would be incredibly slow and technically difficult due to size limits. By using AES for the 1GB file and RSA only for the tiny 32-byte AES key, we get the **speed of AES** and the **secure key sharing of RSA**.