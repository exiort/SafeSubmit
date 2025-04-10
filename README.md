# Anonymous Homework Submission Protocol

This project implements a **secure and anonymous communication protocol** that allows students to submit homework to an instructor without revealing their identities, while ensuring only legitimate students can submit and the instructor can prevent abuse (e.g., duplicate or invalid submissions).

## Features

- Anonymous yet verifiable homework submissions
- RSA-2048 asymmetric cryptography
- AES-256 symmetric encryption
- SHA-256 hashing for message integrity
- Replay attack prevention using timestamps and unique ticket IDs
- Nonce usage for authentication
- Simulation of complete workflow for multiple students

## Protocol Overview

There are three actors in this protocol:

- **Student(s)**: Receives a unique identity (ID) from the organization, and uses it to authenticate submissions anonymously.
- **Instructor**: Accepts anonymous homework submissions.
- **Organization**: A trusted third party that distributes keys and IDs, enabling anonymous and secure communication.

The protocol is split into two main phases:

The steps of the protocol are shown in a format where alphabetical steps represent actions taken by actors at that time, and numerical steps show the dialogue between actors. All steps are presented in an ordered timeline.

### 1. Preparation Phase
- All parties generate RSA key pairs.
- Organization generates AES keys for communication with each student and with the instructor.
- IDs and keys are exchanged securely using RSA and signed with the sender’s private key.
- The instructor receives anonymized student indexes (Sidx).

#### Terms

- `Kpub_x` = Asymmetric public key of x  
- `Kpriv_x` = Asymmetric private key of x  
- `Kx,y` = Symmetric key between x and y  
- `IDx` = Identifier of x  
- `||` = Concatenation  

#### Steps of Preparation Part

```
a-) I, O, S : Creates (Kpub_i, Kpriv_i) pair  
1-) I → O : Kpub_i  
2-) O → I : Kpub_o  
b-) O : Creates IDo , Ko,i  
3-) O → I : EKpub_i(IDo || Ko,i)  
c-) I : DKpriv_i(EKpub_i(IDo || Ko,i))  
d-) I : Checks IDo with Kpub_o  
e-) I : Stores Ko,i  
4-) S → O : Kpub_s  
5-) O → S : Kpub_o  
f-) O : Creates Ko,s, Sidx  
6-) O → S : EKpub_s(IDo || Ko,s || Sidx)  
g-) S : DKpriv_s(EKpub_i(IDo || Ko,s || Sidx))  
h-) S : Checks IDo with Kpub_o  
j-) S : Stores Ko,s  
```

### 2. Submission Phase
- Students request a one-time ticket from the organization.
- Ticket contains timestamp, unique ticket ID, and AES key for instructor communication.
- Students use the ticket to encrypt and submit homework.
- Instructor decrypts and validates submission, ensures it's from a legitimate (but anonymous) student, and sends a signed response with remaining submission attempts.

#### Terms

All terms used in the Preparation part are valid. These are additional:

- `nx,y` = Nonce between x and y  
- `Sidx` = Student index  
- `Ts` = Timestamp  
- `Uticket` = Unique Ticket ID  
- `HW` = Homework of Student  
- `Rt` = Return Message of Instructor  
- `H(M)` = Hash of the Message  

#### Steps of Submitting Part

```
a-) S : Creates IDs , no,s  
1-) S → O : IDs || Sidx || no,s  
b-) O : Checks IDs , Sidx pair  
c-) O : Creates Ts , Uticket , Ks,i  
d-) O : Creates Ticket  // Ticket = EKo,i(Ts || Uticket || Ks,i || Sidx || H(M))  
2-) O → S : Ticket , EKo,s(Ks,i || no,s || H(M))  
e-) S : DKo,s(EKo,s(Ks,i || no,s))  
f-) S : Checks no,s  
g-) S : Creates ns,i  
3-) S → I : Ticket || EKs,i(HW || ns,i || H(M))  
h-) I : DKo,i(Ticket)  
i-) I : Checks Ts , Uticket  
j-) I : Controls Sidx  
l-) I : Accepts HW  
4-) I → S : EKs,i(Rt || ns,i || H(M))  
m-) S : DKs,i(EKs,i(Rt || ns,i))  
n-) S : Checks ns,i  
o-) S : Controls Rt  
```

### Submission Rules:
- Each student has **3 submission attempts**.
- Each ticket is **valid for 5 minutes** and is **one-time use only**.
- Instructor response codes:
  - `>= 0`: Remaining attempts
  - `-1`: No attempts left
  - `-2`: Invalid ticket

## Cryptographic Details

| Component         | Method       |
|------------------|--------------|
| Asymmetric Crypto| RSA-2048     |
| Symmetric Crypto | AES-256 (CBC mode) |
| Hashing          | SHA-256      |
| Signatures       | PKCS#1 v1.5  |



## Project Structure

- `crypto_utils.py` – Contains cryptographic utility functions.
- `organization.py` – Manages key distribution, ticket creation, and authentication.
- `instructor.py` – Accepts and verifies submissions, manages anonymity and attempts.
- `student.py` – Handles handshake, ticket request, and homework submission.
- `simulation.py` – Brings it all together for testing the entire protocol.


## How to Run the Simulation

### 1. Install Requirements

Make sure you have Python 3.12+ installed. Use a virtual environment:

```bash
$python -m venv .venv
$source .venv/bin/activate
$pip install -r requirements.txt
```

### 2. Run Program
Run the simulation by specifying how many students it will run for in simulation.py

```bash
$python simulation.py [NumberOfStudents]
```
