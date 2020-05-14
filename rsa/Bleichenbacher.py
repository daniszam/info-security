import os
import re
import hashlib

from rsa.Rsa import RSA


class Bleichenbacher:

    def __init__(self):
        self.RSA = RSA(1024)

    def generate_signature(self, message):
        digest = hashlib.sha1(message).digest()
        block = b'\x00\x01' + (b'\xff' * (len(digest))) + b'\x00' + ASN1_HASH + digest
        signature = self.RSA.decrypt(int.from_bytes(block, "big"))
        return signature

    def verify_signature(self, message, signature):
        cipher = self.RSA.encrypt(signature)
        block = b'\x00' + cipher.to_bytes((cipher.bit_length() + 7) // 8, "big")
        regex = b'\x00\x01\xff+?\x00.{15}(.{20})'
        pattern = re.compile(regex, re.DOTALL)
        m = pattern.match(block)
        digest = m.group(1)
        return digest == hashlib.sha1(message).digest()


test_text = "hi mom"
ASN1_HASH = os.urandom(15)
rsa = Bleichenbacher()
signature = rsa.generate_signature(test_text.encode())
if rsa.verify_signature(test_text.encode(), signature):
    print("Verified for message - ", test_text)
