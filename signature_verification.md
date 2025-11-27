#### Digital Signature Verification Explanation

This script simulates a secure email using PGP/S/MIME principles. Here is how the signature validation works, satisfying the requirements of Confidentiality, Integrity, and Authenticity.

#### 1. The Creation of the Signature (Alice):
   - Alice took the plaintext message: "Confidential: The Q3 financial report..."
   - She calculated a cryptographic hash (SHA-256) of this message.
   - She Encrypted this hash using her **Private Key**. 
   - This encrypted hash is the "Digital Signature."

#### 2. The Verification of the Signature (Bob):
   - After Bob decrypts the email body (using his Private Key), he has the message and Alice's signature.
   - Bob takes Alice's **Public Key** and decrypts the signature. This reveals the hash Alice calculated.
   - Bob independently calculates the SHA-256 hash of the message he just received.

#### 3. The Validation Logic:
   - Bob compares the hash he calculated vs. the hash he decrypted from the signature.
   - **If they match:**
     1. **Authenticity:** Only Alice has access to her Private Key. Since her Public Key successfully decrypted the signature, it proves Alice created it.
     2. **Integrity:** If even one letter of the message had been changed by a hacker, Bob's calculated hash would be completely different from the signature's hash, and the verification would fail.