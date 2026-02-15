from chacha_aes_util import chacha20_encrypt_decrypt, aes_gcm_encrypt_decrypt
import os
import time # to see the response time of each algorithm (for differentiation purposes)

print("hello Sir Lester AHAHAHAHAHAH")

def main():
    #generating random keys and nonces for both algorithms
    key_chacha = os.urandom(32) #use 32 bytes as well for the chacha
    key_aes = os.urandom(32)  #using 32 bytes for AES-256
    nonce = os.urandom(12)  #nonce must be 12 bytes for both algorithms

    #define plain text
    plaintext = b"Hello, this is a secret message!"

    #chacha20 encryption and decryption
    ciphertext_chacha, decrypted_chacha = chacha20_encrypt_decrypt(key_chacha, nonce, plaintext)
    print("ChaCha20 Ciphertext:", ciphertext_chacha)

    #measure the chachca response time for decryption
    start_chacha = time.perf_counter()
    decrypted_chacha = chacha20_encrypt_decrypt(key_chacha, nonce, plaintext)[1]  #get the decrypted text
    end_chacha = time.perf_counter()
    print("ChaCha20 Decrypted: ", decrypted_chacha)
    chacha_time = end_chacha - start_chacha
    print(f"ChaCha20 Decryption Time: {chacha_time:.6f} seconds")

    #Aes-GCM encryption and decryption
    ciphertext_aes, decrypted_aes = aes_gcm_encrypt_decrypt(key_aes, nonce, plaintext)
    print("AES-GCM Ciphertext: ", ciphertext_aes)

    #Measure the aes response time for decryption
    start_aes = time.perf_counter()
    decrypted_aes = aes_gcm_encrypt_decrypt(key_aes, nonce, plaintext)[1]  #get the decrypted text
    end_aes = time.perf_counter()
    print("AES-GCM Decrypted: ", decrypted_aes)
    aes_time = end_aes - start_aes
    print(f"AES-GCM Decryption Time: {aes_time:.6f} seconds")

    #for the verification of the results
    assert plaintext == decrypted_chacha, "Decryption FAILED for ChaCha20-Poly1305!"
    assert plaintext == decrypted_aes, "Decryption FAILED for AES-GCM!"
    print("Encryption and Decryption successful for both algorithms!")

    #Compare the decryption times of both algorithms
    print("\nPerformance Comparison:")
    if chacha_time < aes_time:
        print(f"ChaCha20-Poly1305 is faster than AES-GCM by {aes_time - chacha_time:.6f} seconds.")
    else:
        print(f"AES-GCM is faster than ChaCha20-Poly1305 by {chacha_time - aes_time:.6f} seconds.")

if __name__ == "__main__":
    main()