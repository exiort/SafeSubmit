from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad



class CryptoUtils:
    @staticmethod
    def generate_rsa():
        key = RSA.generate(2048)
        return key, key.publickey()

    @staticmethod
    def generate_aes(length:int = 32) -> bytes:
        return get_random_bytes(length)

    @staticmethod
    def rsa_encrypt(key, plain_text:bytes) -> bytes:
        cipher = PKCS1_OAEP.new(key)
        return cipher.encrypt(plain_text)

    @staticmethod
    def rsa_decrypt(key, cipher_text:bytes) -> bytes:
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(cipher_text)

    @staticmethod
    def sign(key, message:bytes) -> bytes:
        message_hash = SHA256.new(message)

        signer = pkcs1_15.new(key)
        return signer.sign(message_hash)
    
    @staticmethod
    def verify_sign(key, message, sign) -> bool:
        message_hash = SHA256.new(message)
        verifier = pkcs1_15.new(key)
        try:
            verifier.verify(message_hash, sign)
            return True
        except:
            return False

    @staticmethod
    def aes_encrypt(key:bytes, plain_text:bytes) -> bytes:
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return iv + cipher_text

    @staticmethod
    def aes_decrypt(key:bytes, cipher_text:bytes) -> bytes:
        iv = cipher_text[:16]
        cipher_text = cipher_text[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(cipher_text), AES.block_size)

    @staticmethod
    def hash_sha256(message:bytes) -> bytes:
        hash = SHA256.new()
        hash.update(message)
        return hash.digest()

    @staticmethod
    def compare_sha256_hash(expected:bytes, actual:bytes) -> bool:
        return expected == actual

