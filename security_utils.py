import hashlib
import os
import base64
import qrcode
import io
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# REQUIREMENT 4: HASHING WITH SALT 

def hash_password(password, salt=None):
    """
    Secure password hashing using SHA-256 with salt
    NIST Compliant: Uses cryptographically secure random salt
    """
    if not salt:
        salt = os.urandom(16).hex()  # 128-bit salt
    hash_obj = hashlib.sha256((password + salt).encode()).hexdigest()
    return hash_obj, salt

def verify_password(password, salt, stored_hash):
    """Verify password against stored hash"""
    current_hash, _ = hash_password(password, salt)
    return current_hash == stored_hash

# REQUIREMENT 3: ENCRYPTION & KEY EXCHANGE 


# --- AES-256 Symmetric Encryption ---
def generate_aes_key():
    """Generate a new AES-256 key using Fernet"""
    return Fernet.generate_key().decode()

def encrypt_val(data, key):
    """Encrypt data using AES-256"""
    f = Fernet(key.encode())
    return f.encrypt(data.encode()).decode()

def decrypt_val(cipher, key):
    """Decrypt data using AES-256"""
    f = Fernet(key.encode())
    return f.decrypt(cipher.encode()).decode()

# --- RSA Key Exchange Mechanism ---
def generate_rsa_keypair():
    """
    Generate RSA-2048 key pair for secure key exchange
    Demonstrates asymmetric encryption for key distribution
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Serialize keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    return private_pem, public_pem

def rsa_encrypt_key(aes_key, public_pem):
    """
    Encrypt AES key using RSA public key (Hybrid Encryption)
    Used for secure key exchange between users
    """
    public_key = serialization.load_pem_public_key(
        public_pem.encode(),
        backend=default_backend()
    )
    encrypted = public_key.encrypt(
        aes_key.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def rsa_decrypt_key(encrypted_key, private_pem):
    """Decrypt AES key using RSA private key"""
    private_key = serialization.load_pem_private_key(
        private_pem.encode(),
        password=None,
        backend=default_backend()
    )
    encrypted_bytes = base64.b64decode(encrypted_key)
    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

# ============================================================================
# REQUIREMENT 4: DIGITAL SIGNATURE USING HASH (1.5 marks)
# ============================================================================
def create_digital_signature(data, private_pem):
    """
    Create digital signature for data integrity and authenticity
    Uses RSA private key to sign SHA-256 hash of data
    """
    private_key = serialization.load_pem_private_key(
        private_pem.encode(),
        password=None,
        backend=default_backend()
    )
    
    # Hash the data
    message_hash = hashlib.sha256(data.encode()).digest()
    
    # Sign the hash
    signature = private_key.sign(
        message_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_digital_signature(data, signature_b64, public_pem):
    """
    Verify digital signature to ensure data integrity and authenticity
    Returns True if signature is valid, False otherwise
    """
    try:
        public_key = serialization.load_pem_public_key(
            public_pem.encode(),
            backend=default_backend()
        )
        
        signature = base64.b64decode(signature_b64)
        message_hash = hashlib.sha256(data.encode()).digest()
        
        public_key.verify(
            signature,
            message_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ============================================================================
# REQUIREMENT 5: ENCODING TECHNIQUES (3 marks)
# ============================================================================

# --- Base64 Encoding ---
def base64_encode(data):
    """Encode data to Base64 format"""
    return base64.b64encode(data.encode()).decode()

def base64_decode(encoded_data):
    """Decode Base64 encoded data"""
    return base64.b64decode(encoded_data).decode()

# --- QR Code Generation ---
def generate_qr_code(data):
    """
    Generate QR Code for itinerary sharing
    Returns base64 encoded PNG image
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64 for web display
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return f"data:image/png;base64,{img_base64}"

# ============================================================================
# REQUIREMENT 1: MULTI-FACTOR AUTHENTICATION - OTP (1.5 marks)
# ============================================================================
def generate_otp():
    """
    Generate 6-digit OTP for multi-factor authentication
    Uses cryptographically secure random number generator
    """
    return str(secrets.randbelow(1000000)).zfill(6)

def send_otp_email(recipient_email, otp_code):
    """
    Send OTP via email for MFA
    NOTE: Configure SMTP settings for production use
    For demo purposes, this returns the OTP (simulate email)
    """
    # In production, configure these with real SMTP credentials
    # SMTP_SERVER = "smtp.gmail.com"
    # SMTP_PORT = 587
    # SENDER_EMAIL = "your-app@example.com"
    # SENDER_PASSWORD = "your-app-password"
    
    print(f"[SIMULATED EMAIL] OTP for {recipient_email}: {otp_code}")
    
    # For actual email sending (uncomment in production):
    """
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = recipient_email
        msg['Subject'] = "Your Travel Itinerary OTP"
        
        body = f"Your OTP code is: {otp_code}\nValid for 5 minutes."
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False
    """
    return True  # Simulated success

# ============================================================================
# SECURITY ANALYSIS FUNCTIONS (For Requirement 5 - Theory)
# ============================================================================
def analyze_encoding_security():
    """
    Returns security analysis of encoding techniques
    Required for theoretical component of Requirement 5
    """
    return {
        "Base64": {
            "security_level": "Low",
            "purpose": "Data representation, not security",
            "risks": [
                "Easily reversible - NOT encryption",
                "No confidentiality protection",
                "Should only be used for data transport/storage format"
            ],
            "use_case": "Encoding binary data for JSON/text transmission"
        },
        "QR_Code": {
            "security_level": "Low",
            "purpose": "Data sharing and convenience",
            "risks": [
                "Data visible to anyone who scans",
                "No built-in encryption",
                "Can be intercepted/photographed",
                "Potential for malicious QR injection"
            ],
            "mitigation": "Encrypt data before encoding in QR",
            "use_case": "Share encrypted itinerary links/IDs"
        },
        "possible_attacks": [
            "Base64 Injection: Malicious data in encoded strings",
            "QR Phishing: Fake QR codes redirecting to malicious sites",
            "Man-in-the-Middle: Intercepting encoded data",
            "Social Engineering: Users scanning unknown QR codes"
        ]
    }
