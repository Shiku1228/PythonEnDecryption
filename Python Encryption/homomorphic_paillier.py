from phe import paillier

#key generation
public_key, private_key = paillier.generate_paillier_keypair()

print("Keys generated:\n")

#original numbers (thesee are secrets)
a = 15
b = 20

print("Original Numbers:")
print("a: ", a)
print("b: ", b)

#encrypt the numbers
enc_a = public_key.encrypt(a)
enc_b = public_key.encrypt(b)

print("\nEncrypted values:")
print("Encrypted a:", enc_a)
print("Encrypted b:", enc_b)

#ccompute while encrypted
enc_sum = enc_a + enc_b
enc_mul = enc_a * 3

print("\nComputation performed on encrypted data!")

#Decrypt results
sum_result = private_key.decrypt(enc_sum)
mul_result = private_key.decrypt(enc_mul)

print("\nDecrypted results:")
print("a + b =", sum_result)
print("a * 3 =", mul_result)