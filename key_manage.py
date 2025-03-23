from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PrivateFormat, PublicFormat, NoEncryption
import os, json

# AES Symmetric Encryption
class SymmetricKeyManager:
    def generate_symmetric_key(self):
        return os.urandom(32)  # AES-256 Key
    
    def encrypt(self, key, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.ljust(32)) + encryptor.finalize()
        return iv + ciphertext  # Store IV with ciphertext
    
    def decrypt(self, key, encrypted_data):
        iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext).strip()

# ECC Asymmetric Encryption (Fixed)
class AsymmetricKeyManager:
    def generate_key_pair(self):
        private_key = ec.generate_private_key(ec.SECP384R1())  # ECC for asymmetric encryption
        public_key = private_key.public_key()
        return private_key, public_key
    
    def serialize_keys(self, private_key, public_key):
        private_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        public_pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        return private_pem, public_pem
    
    def load_keys(self, private_pem, public_pem):
        private_key = load_pem_private_key(private_pem, password=None)
        public_key = load_pem_public_key(public_pem)
        return private_key, public_key

# Diffie-Hellman Key Exchange using X25519 (Fixed)
class KeyExchangeManager:
    def generate_dh_key_pair(self):
        private_key = x25519.X25519PrivateKey.generate()  # Corrected X25519 key generation
        public_key = private_key.public_key()
        return private_key, public_key

    def compute_shared_secret(self, private_key, peer_public_key):
        return private_key.exchange(peer_public_key)

# Key Revocation System
class KeyRevocation:
    def __init__(self, revocation_file="revoked_keys.json"):
        self.revocation_file = revocation_file
        if not os.path.exists(revocation_file):
            with open(revocation_file, "w") as file:
                json.dump({}, file)
    
    def revoke_key(self, key_id):
        with open(self.revocation_file, "r+") as file:
            revoked_keys = json.load(file)
            revoked_keys[key_id] = "revoked"
            file.seek(0)
            json.dump(revoked_keys, file)

    def is_key_revoked(self, key_id):
        with open(self.revocation_file, "r") as file:
            revoked_keys = json.load(file)
            return key_id in revoked_keys

# TEST CASES
if __name__ == "__main__":
    # Symmetric Encryption Test
    sym_mgr = SymmetricKeyManager()
    aes_key = sym_mgr.generate_symmetric_key()
    encrypted_data = sym_mgr.encrypt(aes_key, b"Secret Message")
    decrypted_data = sym_mgr.decrypt(aes_key, encrypted_data)
    print("Decrypted Message:", decrypted_data)

    # Asymmetric Encryption Test (Fixed)
    asym_mgr = AsymmetricKeyManager()
    private_key, public_key = asym_mgr.generate_key_pair()
    priv_pem, pub_pem = asym_mgr.serialize_keys(private_key, public_key)
    print("Generated ECC Key Pair")
    
    # Key Exchange Test (Fixed)
    key_ex_mgr = KeyExchangeManager()
    private_a, public_a = key_ex_mgr.generate_dh_key_pair()
    private_b, public_b = key_ex_mgr.generate_dh_key_pair()
    shared_secret_a = key_ex_mgr.compute_shared_secret(private_a, public_b)
    shared_secret_b = key_ex_mgr.compute_shared_secret(private_b, public_a)
    print("Shared Secret Match:", shared_secret_a == shared_secret_b)

    # Key Revocation Test
    revoke_mgr = KeyRevocation()
    revoke_mgr.revoke_key("test_key")
    print("Is Key Revoked?", revoke_mgr.is_key_revoked("test_key"))
