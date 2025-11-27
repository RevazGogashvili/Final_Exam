This script demonstrates a **Hybrid Encryption** system. 
Hybrid encryption combines the efficiency of Symmetric encryption (AES) with the secure key exchange of Asymmetric encryption (RSA).

Why use both?
1. **RSA (Asymmetric)** is secure for sharing keys but is very slow and computationally expensive for large data files.
2. **AES (Symmetric)** is extremely fast and efficient for large messages but requires both parties to already have a shared secret key.

**Step-by-Step:**

#### 1. Setup (User A)
User A creates a **Key Pair** (Public and Private). 
*   **Public Key:** Shared openly. User B uses this to lock the "digital envelope."
*   **Private Key:** Kept secret. Only User A can use this to open the envelope.

#### 2. Encryption (User B)
User B wants to send a secure message ("This is a top secret lab message...").
1.  **Generate Session Key:** User B generates a random 32-byte password (The AES Key).
2.  **Encrypt Message:** User B uses the **AES Key** to encrypt the actual message text. This creates `encrypted_message.bin`.
3.  **Encrypt the Key:** User B cannot just send the AES key in plain text. They use User A's **RSA Public Key** to encrypt the AES key. This creates `aes_key_encrypted.bin`.

#### 3. Transmission
User B sends two files to User A:
1.  The encrypted message (`encrypted_message.bin`).
2.  The locked AES key (`aes_key_encrypted.bin`).

#### 4. Decryption (User A)
User A receives the files.
1.  **Unlock the Key:** User A uses their **RSA Private Key** to decrypt `aes_key_encrypted.bin`. Now User A possesses the shared AES session key.
2.  **Unlock the Message:** User A uses the revealed **AES Key** to decrypt `encrypted_message.bin` and read the original text.