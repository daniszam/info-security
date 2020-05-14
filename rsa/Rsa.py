import math

import sympy as sympy

from Crypto.Util.number import getPrime


class RSA:

    def __init__(self, key_size):
        e = 3
        t = 0
        n = 0

        while math.gcd(e, t) != 1:
            p, q = getPrime(key_size), getPrime(key_size)
            n = p * q
            t = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)

        d = sympy.mod_inverse(e, t)
        self.public_key = (e, n)
        self.private_key = (d, n)

    def encrypt(self, message):
        data = int.from_bytes(message, 'big')
        return pow(data, self.public_key[0], self.public_key[1])

    def decrypt(self, cipher_text):
        number = pow(cipher_text, self.private_key[0], self.private_key[1])
        return number.to_bytes((number.bit_length() + 7) // 8, 'big')

rsa = RSA(256)
message = "Just testing"
cipher_text = rsa.encrypt(message.encode())
decrypter = rsa.decrypt(cipher_text)
print(decrypter)
