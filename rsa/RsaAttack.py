import sympy

from rsa.Rsa import RSA


def RsaAttack(message, rsa_1: RSA, rsa_2: RSA, rsa_3: RSA):
    cipher_1 = rsa_1.encrypt(message)
    cipher_2 = rsa_2.encrypt(message)
    cipher_3 = rsa_3.encrypt(message)

    pub_key_1 = rsa_1.public_key
    pub_key_2 = rsa_2.public_key
    pub_key_3 = rsa_3.public_key

    m_s_1 = pub_key_2[1] * pub_key_3[1]
    m_s_2 = pub_key_1[1] * pub_key_3[1]
    m_s_3 = pub_key_1[1] * pub_key_2[1]

    N_012 = pub_key_1[1] * pub_key_2[1] * pub_key_3[1]
    result = ((cipher_1 * m_s_1 * sympy.mod_inverse(m_s_1, pub_key_1[1])) + (
            cipher_2 * m_s_2 * sympy.mod_inverse(m_s_2, pub_key_2[1])) + (
                      cipher_3 * m_s_3 * sympy.mod_inverse(m_s_3, pub_key_3[1]))) \
             % N_012

    decrypt = int(pow(result, 1 / 3))
    return decrypt.to_bytes((decrypt.bit_length() + 7) // 8, "big")


message = "Check"
decrypt = RsaAttack(message.encode(), RSA(), RSA(), RSA())
print(decrypt)

