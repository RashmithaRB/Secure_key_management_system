# Cryptographic Key Management System

## Overview
This project implements a cryptographic key management system that includes:
- **AES Symmetric Encryption**: Secure encryption and decryption using AES-256.
- **ECC Asymmetric Encryption**: Generation and serialization of elliptic curve key pairs.
- **Diffie-Hellman Key Exchange**: Secure key exchange using X25519.
- **Key Revocation System**: A mechanism to revoke compromised keys and track revoked keys.

## Prerequisites
Ensure you have the following dependencies installed before running the code:

### Install Required Libraries
```bash
pip install cryptography
```

### Required Modules
- `cryptography.hazmat.primitives.ciphers` (for AES encryption)
- `cryptography.hazmat.primitives.asymmetric` (for ECC and X25519 key exchange)
- `cryptography.hazmat.primitives.kdf` (for key derivation functions)
- `os` (for random key generation)
- `json` (for handling key revocation storage)

---

## Code Explanation

### **1. AES Symmetric Encryption**
- **Class:** `SymmetricKeyManager`
- **Methods:**
  - `generate_symmetric_key()`: Generates a 256-bit AES key.
  - `encrypt(key, plaintext)`: Encrypts the plaintext using AES-CBC mode with a randomly generated IV.
  - `decrypt(key, encrypted_data)`: Decrypts the ciphertext using the provided AES key.
- **Working:**
  - A random 32-byte key is generated.
  - The IV is randomly generated (16 bytes) and appended to the ciphertext.
  - Padding ensures plaintext fits AES block size (16 bytes).

### **2. ECC Asymmetric Encryption**
- **Class:** `AsymmetricKeyManager`
- **Methods:**
  - `generate_key_pair()`: Generates a private and public key using ECC (SECP384R1 curve).
  - `serialize_keys(private_key, public_key)`: Converts keys to PEM format.
  - `load_keys(private_pem, public_pem)`: Loads keys from PEM format.
- **Working:**
  - ECC key pairs are generated using SECP384R1.
  - The keys are serialized for storage or transmission.
  - The keys can be loaded back when needed.

### **3. Diffie-Hellman Key Exchange**
- **Class:** `KeyExchangeManager`
- **Methods:**
  - `generate_dh_key_pair()`: Generates an X25519 key pair.
  - `compute_shared_secret(private_key, peer_public_key)`: Computes a shared secret.
- **Working:**
  - Both parties generate their private and public keys.
  - Each party exchanges public keys and derives the shared secret.
  - The computed secrets match, ensuring a secure key exchange.

### **4. Key Revocation System**
- **Class:** `KeyRevocation`
- **Methods:**
  - `revoke_key(key_id)`: Marks a key as revoked and stores it in a JSON file.
  - `is_key_revoked(key_id)`: Checks if a key is revoked.
- **Working:**
  - The system maintains a JSON file (`revoked_keys.json`).
  - A key can be revoked by adding its identifier.
  - Revocation status is checked against stored records.

---

## Usage
Run the script to execute the test cases:
```bash
python script.py
```
### **Test Cases**
- **Symmetric Encryption:** Encrypts and decrypts a message using AES-256.
- **Asymmetric Key Pair Generation:** Generates, serializes, and prints an ECC key pair.
- **Diffie-Hellman Key Exchange:** Computes and verifies shared secrets.
- **Key Revocation:** Revokes a test key and verifies its revocation status.

---

## Expected Output
```
Decrypted Message: Secret Message
Generated ECC Key Pair
Shared Secret Match: True
Is Key Revoked? True
```

---

## Security Considerations
- AES uses a random IV to ensure encryption uniqueness.
- ECC (SECP384R1) is used for high security in asymmetric encryption.
- X25519 ensures secure and efficient key exchange.
- Key revocation prevents the reuse of compromised keys.

---

## Author
**[RASHMITHA R BANEGRA]**


