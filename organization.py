from crypto_utils import CryptoUtils
import uuid
import time



class Organization:
    __rsa_priv_key = None
    __rsa_pub_key = None
    __students:list[list] = list()#list format: (Sidx, Kos, Spubkey, is_shared) 

    __instructor_pub_key = None
    __instructor_aes_key:bytes


    def __prepare_keys(self, class_size:int) -> None:
        print("Organization Generating RSA Keys:", end="")
        self.__rsa_priv_key, self.__rsa_pub_key = CryptoUtils.generate_rsa()
        print("Done!")
        print("Organization Generating Instructor AES Key:", end="")
        self.__instructor_aes_key = CryptoUtils.generate_aes()
        print("Done!")

        print(f"Organization Generating Student AES keys for {class_size} Students:",end="")
        for _ in range(class_size):
            self.__students.append([uuid.uuid4().hex, CryptoUtils.generate_aes(), None, False])
        print("Done!")
            
    def __init__(self, class_size:int) -> None:
        self.__prepare_keys(class_size)
    
    def share_public_key(self):
        print("Organization Shared It's Public Key.")
        return self.__rsa_pub_key

    def set_public_key(self, key, actor:int) -> None: #0 Means Student 1 Means Instructor
        if actor == 0:
            print("Organization Received a Student Public Key.")
            for student in self.__students:
                if student[2] is  None:
                    student[2] = key
                    break

        elif actor == 1:
            print("Organization Received Instructor Public Key.")
            self.__instructor_pub_key = key
     
    def send_handshake_instructor(self) -> tuple[bytes,...]|None:
        print("Organization Handshaking with Instuctor...")
        if self.__instructor_pub_key is None:
            print("No Instuctor Public Key Defined. Returning...")
            return
        
        sign = CryptoUtils.sign(self.__rsa_priv_key, self.__instructor_aes_key)
        
        message = CryptoUtils.rsa_encrypt(self.__instructor_pub_key, self.__instructor_aes_key)

        auth1 = CryptoUtils.rsa_encrypt(self.__instructor_pub_key, sign[:128])
        auth2 = CryptoUtils.rsa_encrypt(self.__instructor_pub_key, sign[128:])
        print("Organization Shared Handshake!")
        return message, auth1, auth2

    def send_handshake_student(self) -> tuple[bytes,...]|None:
        print("Organization Handshaking with a Student...")
        student = None
        for i in range(len(self.__students)):
            if not self.__students[i][3] and self.__students[i][2] is not None:
                self.__students[i][3] = True
                student = self.__students[i]
                break
                    
        if student is None:
            print("Class is Full. Returning...")
            return
        
        sign = CryptoUtils.sign(self.__rsa_priv_key, student[1] + student[0].encode())
        message = CryptoUtils.rsa_encrypt(student[2], student[1] + student[0].encode())
        auth1 = CryptoUtils.rsa_encrypt(student[2], sign[:128])
        auth2 = CryptoUtils.rsa_encrypt(student[2], sign[128:])
        print("Organization Shared Handshake!")
        return message, auth1, auth2

    def generate_ticket(self, payload:bytes):
        print("Organization Received a Ticket Request.")
        sign = payload[:64]
        p = payload[64:]
        sidx = p[:32].decode()
        nonce = p[32:]

        s = None
        for student in self.__students:
            if student[0] == sidx:
                s = student
        if s is None:
            print("No Student is found with Sidx. Returning...")
            return
        
        try:
            plain_sign = CryptoUtils.aes_decrypt(s[1], sign)
            if not CryptoUtils.compare_sha256_hash(CryptoUtils.hash_sha256(p), plain_sign):
                print("Message is isnt valid. Integrity Failed! Returning...")
                return
        except:
            print("Sidx, Kos isn't matched. Returning...")
            return
        
        Ts = int(time.time()).to_bytes(8)
        Uticket = uuid.uuid4().hex.encode()
        Ksi = CryptoUtils.generate_aes()
        payload = Ts + Uticket + Ksi + sidx.encode() 

        p_hash = CryptoUtils.hash_sha256(payload)
        ticket = CryptoUtils.aes_encrypt(self.__instructor_aes_key, payload+p_hash)
        print("Ticket Created!")

        payload = Ksi + nonce
        p_hash = CryptoUtils.hash_sha256(payload)
        cipher = CryptoUtils.aes_encrypt(s[1], payload+p_hash)
        print("Message Created!")
        
        print("Organization Shared Ticket,Message pair.")
        return ticket, cipher

