"""
CRYPTO UTILITIES MODULE
========================
Concepts Demonstrated:
  1. SHA-256 Hashing (document fingerprint)
  2. HMAC-SHA256 (message authentication code)
  3. RSA-2048 Key Generation (asymmetric cryptography)
  4. RSA Digital Signatures (non-repudiation + authenticity)
  5. RSA Signature Verification
  6. AES-256-CBC Encryption (symmetric, document encryption)
  7. AES-256-CBC Decryption
  8. Base64 Encoding (binary-safe transport)
"""

import hashlib
import hmac as _hmac
import base64
import os
import json
from datetime import datetime, timezone

# ── Third-party (cryptography library) ───────────────────────
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID


# ─────────────────────────────────────────────────────────────
# 1. SHA-256 HASHING
# ─────────────────────────────────────────────────────────────

def sha256_file(file_path: str) -> str:
    """
    Read the file in 4 KB chunks and feed into SHA-256.
    Returns 64-character hex digest — the document's unique fingerprint.
    Even a 1-byte change produces a completely different hash (avalanche effect).
    """
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """SHA-256 hash of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_string(text: str) -> str:
    """SHA-256 hash of a UTF-8 string."""
    return hashlib.sha256(text.encode()).hexdigest()


# ─────────────────────────────────────────────────────────────
# 2. HMAC-SHA256  (Message Authentication Code)
# ─────────────────────────────────────────────────────────────

def generate_hmac(message: str, secret_key: str) -> str:
    """
    HMAC-SHA256 provides integrity + authentication.
    Unlike plain hashing, an attacker cannot forge it without knowing the key.
    """
    mac = _hmac.new(
        secret_key.encode(),
        message.encode(),
        hashlib.sha256
    )
    return mac.hexdigest()


def verify_hmac(message: str, secret_key: str, expected_mac: str) -> bool:
    """Constant-time HMAC comparison (prevents timing attacks)."""
    computed = generate_hmac(message, secret_key)
    return _hmac.compare_digest(computed, expected_mac)


# ─────────────────────────────────────────────────────────────
# 3 & 4. RSA KEY GENERATION + DIGITAL SIGNATURES
# ─────────────────────────────────────────────────────────────

def generate_rsa_keypair(key_size: int = 2048) -> tuple[str, str]:
    """
    Generate RSA-2048 key pair.
    Returns (private_key_pem, public_key_pem) as strings.

    Private key → used by institution to sign documents (kept secret)
    Public key  → shared with verifiers to verify signatures
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return private_pem, public_pem


def sign_hash(doc_hash: str, private_key_pem: str) -> str:
    """
    Create RSA-PSS digital signature over the document hash.
    PSS (Probabilistic Signature Scheme) is the modern, secure padding.
    Returns Base64-encoded signature string.
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    raw_sig = private_key.sign(
        doc_hash.encode(),
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(raw_sig).decode()


def verify_rsa_signature(doc_hash: str, signature_b64: str, public_key_pem: str) -> bool:
    """
    Verify RSA-PSS signature.
    Returns True if the signature was made by the holder of the matching private key.
    """
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )
        public_key.verify(
            base64.b64decode(signature_b64),
            doc_hash.encode(),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────
# 5. AES-256-CBC ENCRYPTION / DECRYPTION
# ─────────────────────────────────────────────────────────────

def generate_aes_key() -> bytes:
    """Generate a cryptographically secure 256-bit (32-byte) AES key."""
    return os.urandom(32)


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7 padding — pads data to a multiple of block_size."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding."""
    return data[: -data[-1]]


def aes_encrypt(data: bytes, key: bytes) -> dict:
    """
    AES-256-CBC encryption.
    A random 16-byte IV is generated per encryption for semantic security
    (same plaintext → different ciphertext each time).
    Returns: { ciphertext_b64, iv_b64 }
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(_pkcs7_pad(data)) + enc.finalize()
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "iv":         base64.b64encode(iv).decode(),
    }


def aes_decrypt(ciphertext_b64: str, iv_b64: str, key: bytes) -> bytes:
    """Decrypt AES-256-CBC ciphertext back to plaintext bytes."""
    ct = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    return _pkcs7_unpad(dec.update(ct) + dec.finalize())


# ─────────────────────────────────────────────────────────────
# KEY MANAGEMENT HELPERS
# ─────────────────────────────────────────────────────────────

KEYS_DIR = "keys"
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "institution_private.pem")
PUBLIC_KEY_PATH  = os.path.join(KEYS_DIR, "institution_public.pem")
AES_KEY_PATH     = os.path.join(KEYS_DIR, "aes_key.bin")
CERTIFICATE_PATH = os.path.join(KEYS_DIR, "institution_certificate.pem")


def load_or_create_keys() -> tuple[str, str, bytes]:
    """
    Load existing keys from disk, or generate and save new ones.
    Returns (private_key_pem, public_key_pem, aes_key_bytes)
    """
    os.makedirs(KEYS_DIR, exist_ok=True)

    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        with open(PRIVATE_KEY_PATH) as f:
            private_pem = f.read()
        with open(PUBLIC_KEY_PATH) as f:
            public_pem = f.read()
    else:
        private_pem, public_pem = generate_rsa_keypair()
        with open(PRIVATE_KEY_PATH, "w") as f:
            f.write(private_pem)
        with open(PUBLIC_KEY_PATH, "w") as f:
            f.write(public_pem)

    if os.path.exists(AES_KEY_PATH):
        with open(AES_KEY_PATH, "rb") as f:
            aes_key = f.read()
    else:
        aes_key = generate_aes_key()
        with open(AES_KEY_PATH, "wb") as f:
            f.write(aes_key)

    return private_pem, public_pem, aes_key


def create_self_signed_certificate(private_key_pem: str, public_key_pem: str, common_name: str = "SecureDoc Institution") -> str:
    """Create a self-signed X.509 certificate for PKI-style verification."""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend(),
    )
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend(),
    )
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureDoc Verification Authority"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now.replace(year=now.year + 5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def load_or_create_certificate(private_key_pem: str, public_key_pem: str) -> str:
    """Load an existing institution certificate or mint a fresh self-signed one."""
    os.makedirs(KEYS_DIR, exist_ok=True)
    if os.path.exists(CERTIFICATE_PATH):
        with open(CERTIFICATE_PATH, "r", encoding="utf-8") as f:
            return f.read()
    certificate_pem = create_self_signed_certificate(private_key_pem, public_key_pem)
    with open(CERTIFICATE_PATH, "w", encoding="utf-8") as f:
        f.write(certificate_pem)
    return certificate_pem


def sign_with_certificate(message: str, private_key_pem: str) -> str:
    """Sign message material for PKI-backed document verification."""
    return sign_hash(message, private_key_pem)


def verify_certificate_signature(message: str, signature_b64: str, certificate_pem: str) -> bool:
    """Verify a message signature using the public key embedded in the certificate."""
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode(), default_backend())
        public_key = certificate.public_key()
        public_key.verify(
            base64.b64decode(signature_b64),
            message.encode(),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def certificate_summary(certificate_pem: str) -> dict:
    """Expose issuer/subject fields for UI and audit output."""
    try:
        cert = x509.load_pem_x509_certificate(certificate_pem.encode(), default_backend())
        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": str(cert.serial_number),
            "not_valid_before": cert.not_valid_before.isoformat(),
            "not_valid_after": cert.not_valid_after.isoformat(),
        }
    except Exception:
        return {}


# ─────────────────────────────────────────────────────────────
# CERTIFICATE / METADATA HELPER
# ─────────────────────────────────────────────────────────────

def build_document_record(
    filename: str,
    doc_hash: str,
    student_name: str,
    degree: str,
    institution: str,
    signature: str,
    public_key_pem: str,
    metadata: dict,
    original_file_path: str,
    encrypted_file_path: str = "",
    encrypted: bool = False,
    document_type: str = "",
    document_category: str = "Academic",
    certificate_pem: str = "",
    certificate_signature: str = "",
    content_certificate_signature: str = "",
) -> dict:
    """
    Build the JSON record that gets stored on the blockchain.
    """
    return {
        "document_name": filename,
        "document_type": document_type,
        "document_category": document_category,
        "document_hash": doc_hash,
        "student_name": student_name,
        "degree": degree,
        "institution": institution,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "signature": signature,
        "public_key": public_key_pem,
        "certificate_pem": certificate_pem,
        "certificate_signature": certificate_signature,
        "content_certificate_signature": content_certificate_signature,
        "hmac": generate_hmac(doc_hash, "INSTITUTION_SECRET_2024"),
        "encrypted": encrypted,
        "original_file_path": original_file_path,
        "encrypted_file_path": encrypted_file_path,
        "metadata": metadata,
    }
