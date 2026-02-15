#simulated approach only
#PQC + AES GCM

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

"""
Simulalating PQC key exchange:
normallly, each user will use NNTRU/Kyber to exchange a shared secret message
BBBut we'll do  it wuth a random 32-byte keys.
"""
alice_shared_key = os.urandom(32)
bob_shared_key = alice_shared_key #derived from PCQ KEM

print("Simulated shared key (hex): ", alice_shared_key.hex())

#User  encrypts messaage using AES-GCM
message = b"Hello, this message is a PQC demo message."
aes = AESGCM(alice_shared_key)
nonce = os.urandom(12)
ciphertext = aes.encrypt(nonce, message, None)
print("Encrypted message (hex): ", ciphertext.hex())

#User 2 decrypts the message
decrypted = AESGCM(bob_shared_key).decrypt(nonce, ciphertext, None)
print("Decrypted message:", decrypted.decode())

#Explanation of the process
print("\nNote:")
print("1. Shared secret is simulated to represent a quantum-resistant key exchange (NTRU/Kyber).")
print("2. AES-GCM encrypts the actual message using the shared secret.")
print("3. This demonstrates the PQC workflow even without the real PQC library.")


