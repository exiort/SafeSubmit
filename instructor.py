from crypto_utils import CryptoUtils
import time
import struct



class Instructor:
    __rsa_priv_key = None
    __rsa_pub_key = None

    __organization_pub_key = None
    __organization_aes_key:bytes|None

    __accepted_homeworks:list[list] #list format: (Sidx, Hw, remaining_attempt)

    __expired_ticket_ids:list
    
    def __prepare_keys(self) -> None:
        print("Instuctor Generating RSA Keys:", end="")
        self.__rsa_priv_key, self.__rsa_pub_key = CryptoUtils.generate_rsa()
        print("Done!")
        
    def __init__(self) -> None:
        self.__prepare_keys()
        self.__accepted_homeworks = list()
        self.__organization_aes_key = None
        self.__expired_ticket_ids = list()
        
    def share_public_key(self):
        print("Instuctor Shared Their Public Key.")
        return self.__rsa_pub_key

    def set_public_key(self, key) -> None:
        print("Instructor Receiver Organization Public Key.")
        self.__organization_pub_key = key

    def accept_handshake_organization(self, payload:bytes, auth1:bytes, auth2:bytes):
        print("Instuctor Handshaking with Organization...")
        if self.__organization_pub_key is None:
            print("No Organization Public Key Defined. Returning...")
            return

        a1 = CryptoUtils.rsa_decrypt(self.__rsa_priv_key, auth1)
        a2 = CryptoUtils.rsa_decrypt(self.__rsa_priv_key, auth2)
        key = CryptoUtils.rsa_decrypt(self.__rsa_priv_key, payload)

        if not CryptoUtils.verify_sign(self.__organization_pub_key, key, a1+a2):
            print("Validating Organization Sign Failed! Returning...")
            return
        
        self.__organization_aes_key = key
        print("Instuctor Handshaked!")
        
    def accept_homework(self, ticket:bytes, payload:bytes) -> bytes|None:
        print("Instuctor Received Homework.")
        if self.__organization_aes_key is None:
            print("No Organization AES Key Defined. Returning...")
            return

        plain_ticket = CryptoUtils.aes_decrypt(self.__organization_aes_key, ticket)        
        
        Ts = plain_ticket[:8]
        Uticket = plain_ticket[8:40]
        Ksi = plain_ticket[40:72]
        Sidx = plain_ticket[72:104].decode()
        hash_ticket = plain_ticket[104:]

        if not CryptoUtils.compare_sha256_hash(CryptoUtils.hash_sha256(plain_ticket[:104]), hash_ticket):
            print("Ticket Hash Isnt Valid. Integrity Failed! Returning...")
            return

        plain_payload = CryptoUtils.aes_decrypt(Ksi, payload)

        hw = plain_payload[:32]
        nonce = plain_payload[32:64]
        hash_payload = plain_payload[64:]

        if not CryptoUtils.compare_sha256_hash(CryptoUtils.hash_sha256(plain_payload[:64]), hash_payload):
            print("Message Hash Isnt Valid. Integrity Failed! Returning...")
            return

        Ts = struct.unpack("!Q", Ts)[0]
        if time.time() - Ts > 300 or Uticket in self.__expired_ticket_ids:
            print("Either Ticket Lifetime is Expired or Ticket Id expired. Homework isnt Accepted!")
            ret = -2
        else:
            self.__expired_ticket_ids.append(Uticket)
            
            s = None
            for student in self.__accepted_homeworks:
                if student[0] == Sidx:
                    s = student

            if s is not None:
                if s[2] == 0:
                    print("Student Has No Remaining Submit Attempts. Homework isnt Accepted")
                    ret = -1
                else:
                    s[1] = hw
                    s[2] -= 1
                    ret = s[2]
                    print("Homework Accpeted!")
            else:
                self.__accepted_homeworks.append([Sidx, hw, 2])
                ret = 2
                print("Homework Accepted!")

        payload = ret.to_bytes(1, signed=True) + nonce
        p_hash = CryptoUtils.hash_sha256(payload)
        cipher = CryptoUtils.aes_encrypt(Ksi, payload+p_hash)
        print("Instuctor Shared Ack.")
        return cipher

    def homeworks_results(self):
        print(f"Instuctor Accepted:{len(self.__accepted_homeworks)} Homework.")
        print("From:")
        for student in self.__accepted_homeworks:
            print(student[0])
