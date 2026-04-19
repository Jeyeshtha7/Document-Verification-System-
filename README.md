# Document-Verification-System-

A blockchain-based system to verify the authenticity and integrity of academic documents using cryptographic techniques like hashing, encryption, and digital signatures.

## Overview

This project ensures that uploaded documents are secure, verifiable, and tamper-proof by combining:

Cryptography (SHA-256, RSA, AES)
Blockchain technology
Digital signatures

##  Features
 SHA-256 hashing for integrity
 RSA digital signatures for authentication
 AES encryption for secure storage
 Blockchain-based verification
 Merkle Tree implementation
 Proof of Work (PoW)
 Multi-format document support (PDF, DOCX, Images, TXT)
 Tamper detection system

 ### Tech Stack
Backend: Python (Flask)
Cryptography: hashlib, hmac, RSA, AES
Blockchain: Custom implementation
File Handling: PyPDF2, python-docx, OpenCV

## Installation
git clone <your-repo-url>
cd secure_doc_verification
python -m venv venv
Activate environment

Windows

venv\Scripts\activate

Mac/Linux

source venv/bin/activate
pip install -r requirements.txt

##  Run the Application
python app.py

Open in browser:

http://127.0.0.1:5000/

### Workflow
Upload document
Generate SHA-256 hash
Sign hash using RSA
Store in blockchain
Verify by comparing hashes and validating chain
