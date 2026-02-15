from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
import os  #used for generating random keys and nonces 

#for ChaCha20-Poly1305, the key must be 32 bytes and the nonce must be 12 bytes CHACHA20-Poly1305
"""
using the Chacha20 === creates object using the provided key and then encrypts the plaintext using the provided nonce. 
The resulting ciphertext is then decrypted using the same nonce to verify that the original plaintext is correctly retrieved. 
The function returns both the ciphertext and the decrypted plaintext for comparison.
Returning both the ciphertext and decrypted plaintext allows us to verify that the encryption and decryption processes are working correctly by 
comparing the original plaintext with the decrypted output.
"""

def chacha20_encrypt_decrypt(key, nonce, plaintext):
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, plaintext, None)
    decrypted = chacha.decrypt(nonce, ciphertext, None)
    return ciphertext, decrypted


#for AES-GCM, the key can be either 16, 24, or 32 bytes and the nonce must be 12 bytes AES-GCM
"""
The result is similar to the ChaCha20-Poly1305 function, but it uses AES-GCM for encryption and decryption.
A unique value (12 bytes nonce) is used for each encryption operation to ensure security. 
The function returns both the ciphertext and the decrypted plaintext for verification.
"""
def aes_gcm_encrypt_decrypt(key, nonce, plaintext):
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    return ciphertext, decrypted