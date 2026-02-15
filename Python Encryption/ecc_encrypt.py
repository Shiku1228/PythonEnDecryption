from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

#==== generate ECC Keys for Alice and Bob
alice_private = ec.generate_private_key(ec.SECP256R1())
alice_public = alice_private.public_key()

bob_private = ec.generate_private_key(ec.SECP256R1())
bob_public = bob_private.public_key()

#====ECDH shared secret ===
alice_shared = alice_private.exchange(ec.ECDH(), bob_public)
bob_shared = bob_private.exchange(ec.ECDH(), alice_public)

#===== deriviation AES keys from shared secret ===

def derive_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt= None,
        info = b'ecc-lab',
    ).derive(shared_secret)

alice_key = derive_key(alice_shared)
bob_key = derive_key(bob_shared)

#== encrypt the mmessage
message = "Hello, this message is encrypted using ECC + AES"
aes = AESGCM(alice_key)
nonce = os.urandom(12)
ciphertext = aes.encrypt(nonce, message.encode(), None)
print("Encrypted (hex): ", ciphertext.hex())


#=== decrypt the message
decrypted = AESGCM(bob_key).decrypt(nonce, ciphertext, None).decode()
print("Decrypted message:", decrypted)
