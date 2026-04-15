# Document-Verification-System-

##  Overview

This project is a ** Document Verification System** that helps detect whether a document is **original or tampered**. It uses **SHA-256 hashing** to generate a unique fingerprint for each file and verifies authenticity through QR code scanning.

---

##  Features

*  Upload documents (PDF/Image)
*  Generate secure **SHA-256 hash**
*  Create QR code linked to document data
*  Scan QR code for verification
*  Detect **original vs tampered files**
*  Track scan attempts
*  User authentication system (optional)

---

##  Tech Stack

###  Backend

* Python
* Flask

###  Frontend

* React.js
* HTML, CSS

###  Security

* SHA-256 Hashing

###  Libraries

* hashlib (hash generation)
* qrcode (QR generation)
* sqlite3 (database)
* os (file handling)

###  Additional Tools

* Node.js

###  Database

* SQLite

---

##  How It Works

1. User uploads a document
2. System generates a **SHA-256 hash**
3. QR code is created with document details
4. Data is stored in database
5. User scans QR code
6. System compares stored hash with current file
7. Result:

   * ✅ Match → Original
   * ❌ Mismatch → Tampered

---

##  Project Structure

```
project/
│
├── backend/
│   ├── app.py
│   ├── verify.py
│   ├── database.db
│
├── frontend/
│   ├── React App
│
├── uploads/
│   ├── stored documents
│
├── qr_codes/
│   ├── generated QR images
│
├── server.js
└── README.md
```

---

##  Installation & Setup

### 1. Clone Repository

```
git clone <your-repo-link>
cd project
```

### 2. Backend Setup

```
pip install flask qrcode
python app.py
```

### 3. Frontend Setup

```
cd frontend
npm install
npm start
```

### 4. (Optional) Node Server

```
npm install
node server.js
```

---

##  Use Cases

*  Certificate verification (colleges)
*  Official document validation
*  Resume authenticity check
*  Fraud detection systems

---
