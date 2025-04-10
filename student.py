from crypto_utils import CryptoUtils
import uuid
from Crypto.Random import get_random_bytes


class Student:
    __rsa_priv_key = None
    __rsa_pub_key = None

    __name:str
    __Sidx:str
    
    __organization_pub_key = None
    __organization_aes_key:bytes|None

    __last_nonce = None
    
    __valid_ticket:bytes|None
    __valid_instructor_aes_key:bytes|None

    __is_hw_send:bool
    __is_hw_accepted:bool

    def __prepare_keys(self) -> None:
        print(f"Student_{self.__name} Generating RSA Keys:", end="")
        self.__rsa_priv_key, self.__rsa_pub_key = CryptoUtils.generate_rsa()
        print("Done!")
        
    def __init__(self, name:str) -> None:
        self.__name = name
        self.__prepare_keys()
        self.__organization_aes_key = None
        self.__valid_ticket = None
        self.__valid_instructor_aes_key = None
        self.__is_hw_send = False
        self.__is_hw_accepted = False
        
    def share_public_key(self):
        print(f"Student_{self.__name} Shared Their Public Key.")
        return self.__rsa_pub_key

    def set_public_key(self, key) -> None:
        print(f"Student_{self.__name} Received Organization Public Key.")
        self.__organization_pub_key = key

    def accept_handshake_organization(self, payload:bytes, auth1:bytes, auth2:bytes):
        print(f"Student_{self.__name} Handshaking with Organization...")
        if self.__organization_pub_key is None:
            print("No Organization Public Key Defined. Returning...")
            return

        a1 = CryptoUtils.rsa_decrypt(self.__rsa_priv_key, auth1)
        a2 = CryptoUtils.rsa_decrypt(self.__rsa_priv_key, auth2)
        p = CryptoUtils.rsa_decrypt(self.__rsa_priv_key, payload)

        if not CryptoUtils.verify_sign(self.__organization_pub_key, p, a1+a2):
            print("Validating Organization Sign Failed! Returning...")
            return

        self.__organization_aes_key = p[:32]
        self.__Sidx = p[32:].decode()
        print(f"Student_{self.__name} Handshaked!")
        
    def request_ticket(self) -> bytes|None:
        print(f"Student_{self.__name} Creates A Ticket Request...")
        if self.__organization_aes_key is None:
            print("No Organization AES Key Defined. Returning...")
            return
        
        nonce = uuid.uuid4().hex.encode()
        self.__last_nonce = nonce
        
        payload = self.__Sidx.encode() + nonce
        sign = CryptoUtils.aes_encrypt(self.__organization_aes_key, CryptoUtils.hash_sha256(payload))

        print(f"Student_{self.__name} Shared Ticket Request.")
        return sign + payload

    def accept_ticket(self, ticket, payload) -> None:
        print(f"Student_{self.__name} Receive a Ticket.")
        if self.__organization_aes_key is None:
            print("No Organization AES Key Defined. Returning...")
            return
        
        plain_payload = CryptoUtils.aes_decrypt(self.__organization_aes_key, payload) 
        p = plain_payload[:64]
        sign = plain_payload[64:]

        if not CryptoUtils.compare_sha256_hash(CryptoUtils.hash_sha256(p), sign):
            print("Message Hash Isnt Valid. Integrity Failed! Returning...")
            return

        Ksi = p[:32]
        nonce = p[32:]
        
        if not self.__last_nonce == nonce:
            print("Nonce Isnt Valid. Authentication Failed! Returning...")
            return

        self.__valid_instructor_aes_key = Ksi
        self.__valid_ticket = ticket
        print(f"Student_{self.__name} Accepted Ticket!")

    def submit_homework(self) -> tuple[bytes,...]|None:
        print(f"Student_{self.__name} Preparing Homework.")
        if self.__valid_instructor_aes_key is None or self.__valid_ticket is None:
            print("Neither Valid Instuctor AES Key nor Valid Ticket! Returning...")
            return

        hw = get_random_bytes(32)
        nonce = uuid.uuid4().hex.encode()
        self.__last_nonce = nonce
        
        payload = hw + nonce
        p_hash = CryptoUtils.hash_sha256(payload)

        cipher = CryptoUtils.aes_encrypt(self.__valid_instructor_aes_key, payload+p_hash)

        self.__is_hw_send = True
        print(f"Student_{self.__name} Shared Ticket,Homework Pair.")
        return self.__valid_ticket, cipher

    def receive_submit_result(self, payload:bytes) -> None:
        print(f"Student_{self.__name} Recevied Submit Result")
        if self.__valid_instructor_aes_key is None:
            print("No Valid Instructor AES Key! Returning...")
            return

        plain_payload = CryptoUtils.aes_decrypt(self.__valid_instructor_aes_key, payload)
        ret = int.from_bytes(plain_payload[:1], signed=True)
        nonce = plain_payload[1:33]
        hash_payload = plain_payload[33:]

        if not CryptoUtils.compare_sha256_hash(CryptoUtils.hash_sha256(plain_payload[:33]), hash_payload):
            print("Message Hash Isnt Valid. Integrity Failed! Returning...")
            return

        if not nonce == self.__last_nonce:
            print("Nonce Isnt Valid. Authentication Failed! Returning...")
            return

        if ret >= 0:
            print("Homework is Accepted!")
            self.__is_hw_accepted = True
        else:
            self.__is_hw_accepted = False
            print("Homework Isnt Accepted Due:", end="")
            if ret == -1:
                print("Insufficient Submit Attempts")
            elif ret == -2:
                print("Invalid Ticket!")

    def submission_result(self) -> None:
        print(f"Student_{self.__name} thinks, Homework is", end="")
        if not self.__is_hw_send:
            print("nt",end="")
        print(" send, and", end="")
        if not self.__is_hw_accepted:
            print("not", end="")
        print(" accepted!")
