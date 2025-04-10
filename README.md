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

### 1. Preparation Phase
- All parties generate RSA key pairs.
- Organization generates AES keys for communication with each student and with the instructor.
- IDs and keys are exchanged securely using RSA and signed with the sender’s private key.
- The instructor receives anonymized student indexes (Sidx).

### 2. Submission Phase
- Students request a one-time ticket from the organization.
- Ticket contains timestamp, unique ticket ID, and AES key for instructor communication.
- Students use the ticket to encrypt and submit homework.
- Instructor decrypts and validates submission, ensures it's from a legitimate (but anonymous) student, and sends a signed response with remaining submission attempts.

### Submission Rules:
- Each student has **3 submission attempts**.
- Each ticket is **valid for 5 minutes** and is **one-time use only**.
- Instructor response codes:
  - `>= 0`: Remaining attempts
  - `-1`: No attempts left
  - `-2`: Invalid ticket

## 🔒 Cryptographic Details

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

> These modules are combined in `all.py` for single-script convenience.

## How to Run the Simulation

### 1. Install Requirements

Make sure you have Python 3.12+ installed. Use a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
