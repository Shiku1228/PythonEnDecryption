import random

# Secret (known only to Prover)
secret_x = 5  # Prover knows x

# Public value
p = 11  # prime
v = (secret_x ** 2) % p  # v = 25 % 11 = 3
print("Public value v:", v)

# Zero-Knowledge Proof protocol (simplified)
# Prover commits
r = random.randint(1, p-1)
commit = (r ** 2) % p
print("Prover sends commitment:", commit)

# Verifier sends random challenge
challenge = random.randint(0, 1)
print("Verifier challenge:", challenge)

# Prover responds
if challenge == 0:
    response = r
else:
    response = (r * secret_x) % p
print("Prover response:", response)

# Verifier checks
if challenge == 0:
    assert (response ** 2) % p == commit
else:
    assert (response ** 2) % p == (commit * v) % p

print("Zero-Knowledge Proof verified ✅")
