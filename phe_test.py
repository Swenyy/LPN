from phe import paillier
from time import  time

public_key, private_key = paillier.generate_paillier_keypair(n_length=128)
secret_number_list = [3.141592653, 300, -4.6e-12]
t1 = time()
encrypted_number_list = [public_key.encrypt(x) for x in secret_number_list]
t2 = time()
print('encrypt:')
print(t2-t1)

t1 = time()
[private_key.decrypt(x) for x in encrypted_number_list]
t2 = time()
print('decrypt:')
print(t2-t1)