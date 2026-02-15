from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

#Alice Keys
with open(r"C:/Users/RENZ S. LATANGGA/PycharmProjects/PythonEnDecryption/Python Encryption/KEY/alice_private.pem", "rb") as f:
    alice_private = serialization.load_pem_private_key(f.read(), password=None)

with open(r"C:/Users/RENZ S. LATANGGA/PycharmProjects/PythonEnDecryption/Python Encryption/KEY/alice_public.pem", "rb") as f:
    alice_public = serialization.load_pem_public_key(f.read())



# Bob keys
with open(r"C:/Users/RENZ S. LATANGGA/PycharmProjects/PythonEnDecryption/Python Encryption/KEY/bob_private.pem", "rb") as f:
    bob_private = serialization.load_pem_private_key(f.read(), password=None)
with open(r"C:/Users/RENZ S. LATANGGA/PycharmProjects/PythonEnDecryption/Python Encryption/KEY/bob_public.pem", "rb") as f:
    bob_public = serialization.load_pem_public_key(f.read())

# === ECDH shared secret ===
alice_shared = alice_private.exchange(ec.ECDH(), bob_public)
bob_shared = bob_private.exchange(ec.ECDH(), alice_public)

# === Derive AES key from shared secret ===
def derive_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecc-lab',
    ).derive(shared_secret)

alice_key = derive_key(alice_shared)
bob_key = derive_key(bob_shared)

# === Encrypt message (Alice sends) ===
message = "Hello! This is a message using OpenSSL keys"
aes = AESGCM(alice_key)
nonce = os.urandom(12)
ciphertext = aes.encrypt(nonce, message.encode(), None)
print("Encrypted (hex):", ciphertext.hex())

# === Decrypt message (Bob receives) ===
decrypted = AESGCM(bob_key).decrypt(nonce, ciphertext, None).decode()
print("Decrypted message:", decrypted)
