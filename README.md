# Secure Travel Itinerary Application
## NIST SP 800-63-2 Compliant Security Implementation

![Security Badge](https://img.shields.io/badge/Security-NIST%20Compliant-brightgreen)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-blue)
![MongoDB](https://img.shields.io/badge/Database-MongoDB%20Atlas-green)

An educational demonstration of comprehensive security implementation including authentication, authorization, encryption, hashing, digital signatures, and encoding techniques.

---

## 🎯 Overview

This application implements all security concepts required by the **NIST SP 800-63-2 E-Authentication Architecture** standard:

- **Multi-Factor Authentication** (Password + OTP Email)
- **Role-Based Access Control** (3 Roles × 2 Objects)
- **AES-256 + RSA-2048 Hybrid Encryption**
- **SHA-256 Password Hashing with Salt**
- **RSA-2048 Digital Signatures**
- **Base64 Encoding & QR Code Generation**

Perfect for learning security concepts or preparing for viva evaluations!

---

## 🔐 Security Features

### 1. Authentication (Multi-Factor)
```
Single-Factor: Password with SHA-256 hashing + 128-bit salt
Multi-Factor:  Email OTP (6-digit, 5-minute validity)
Account Protection: 5-attempt lockout
```

### 2. Authorization (Access Control)
```
3 Subjects: Admin | Traveler | Guest
2 Objects:  Itineraries | Bookings

Admin:     Full access (create, read, update, delete, share, verify)
Traveler:  Own data + sharing (create, read, update, delete, share, verify)
Guest:     Read-only access
```

### 3. Encryption
```
Symmetric:   AES-256 for data encryption (fast)
Asymmetric:  RSA-2048 for key exchange (secure)
Approach:    Hybrid encryption (best of both worlds)
```

### 4. Hashing & Integrity
```
Password Hashing:  SHA-256 with random salt
Digital Signature: RSA-2048 signed hashes
Tamper Detection:  Invalid signatures alert data modification
```

### 5. Encoding
```
Base64:  Safe text transmission of binary data
QR Code: 2D barcode for easy itinerary sharing
```

---

## 📁 Project Structure

```
secure-travel-itinerary/
├── app.py                    # Main Flask application (API endpoints)
├── security_utils.py         # Encryption, hashing, signatures
├── database.py               # MongoDB config + Access Control Matrix
├── requirements.txt          # Python dependencies
├── templates/
│   ├── index.html           # Login/Register page
│   ├── dashboard.html       # Main dashboard
│   └── shared_itinerary.html # Public itinerary view
└── README.md                # This file
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- MongoDB Atlas Account (free tier available)
- Git

### Installation

```bash
# Clone repository
git clone https://github.com/yokshith09/secure-travel-itinerary.git
cd secure-travel-itinerary

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set MongoDB connection
export MONGO_URI="mongodb+srv://username:password@cluster.xxxxx.mongodb.net/?appName=Cluster0"

# Run application
python app.py
```

### Access Application
- **URL**: http://localhost:5000/
- **Sample Credentials**:
  - Email: john@travel.com
  - Password: Travel@123
  - OTP: Check console output

---

## 📚 API Documentation

### Authentication Endpoints

**Register User**
```bash
POST /api/register
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "SecurePass123",
  "role": "traveler"
}
```

**Login (Step 1: Password)**
```bash
POST /api/login
{
  "email": "john@example.com",
  "password": "SecurePass123"
}
Response: OTP sent to email
```

**Verify OTP (Step 2: MFA)**
```bash
POST /api/verify-otp
{
  "email": "john@example.com",
  "otp": "042857"
}
Response: Authenticated session created
```

### Itinerary Endpoints

**Create Encrypted Itinerary**
```bash
POST /api/itinerary
{
  "tripName": "Paris Summer 2026",
  "destination": "Paris, France",
  "startDate": "2026-06-01",
  "endDate": "2026-06-30",
  "flightDetails": "Flight AF123, 10:00 AM",
  "hotelDetails": "Hotel Royale, 5-star"
}
Response: Encrypted data + QR code + Digital signature
```

**Get My Itineraries (Decrypted)**
```bash
GET /api/my_itineraries
Response: All user's itineraries with decrypted data
```

**Verify Digital Signature**
```bash
GET /api/itinerary/<id>/verify
Response: Signature validation status
```

**Share Itinerary**
```bash
POST /api/itinerary/<id>/share
{
  "email": "guest@example.com"
}
```

### Booking Endpoints

**Create Signed Booking**
```bash
POST /api/booking
{
  "itinerary_id": "507f1f77bcf86cd799439012",
  "booking_reference": "BK-2026-12345",
  "amount": 1200.00
}
Response: Booking with digital signature
```

**Verify Booking Signature**
```bash
GET /api/booking/<id>/verify
Response: Signature validation + decoded reference
```

### Access Control Endpoints

**Check Permissions**
```bash
POST /api/access-control/check
{
  "object": "itineraries",
  "action": "delete"
}
Response: allowed (true/false) + reason
```

**Get Access Summary**
```bash
GET /api/access-control/summary
Response: Role permissions + policy justification
```

---

## 💾 Database Schema

### Users Collection
```javascript
{
  "_id": ObjectId,
  "name": "John Doe",
  "email": "john@example.com",
  "role": "traveler",
  "password_hash": "SHA256_HASH",
  "salt": "RANDOM_128_BIT",
  "rsa_private_key": "PRIVATE_KEY_PEM",
  "rsa_public_key": "PUBLIC_KEY_PEM",
  "mfa_enabled": true,
  "failed_attempts": 0,
  "is_locked": false,
  "created_at": ISODate
}
```

### Itineraries Collection
```javascript
{
  "_id": ObjectId,
  "tripName": "Paris Summer 2026",
  "destination": "Paris, France",
  "startDate": "2026-06-01",
  "endDate": "2026-06-30",
  "flightDetails": "ENCRYPTED_DATA",
  "hotelDetails": "ENCRYPTED_DATA",
  "aes_key": "ENCRYPTION_KEY",
  "signature": "RSA_SIGNED_HASH",
  "owner": "john@example.com",
  "shared_with": ["guest@example.com"],
  "created_at": ISODate
}
```

### Bookings Collection
```javascript
{
  "_id": ObjectId,
  "itinerary_id": ObjectId,
  "booking_reference": "BK-2026-12345",
  "encoded_reference": "BASE64_ENCODED",
  "amount": 1200.00,
  "signature": "RSA_SIGNED_HASH",
  "user_email": "john@example.com",
  "status": "confirmed",
  "created_at": ISODate
}
```

---

## 🔒 How Security Works

### 1. Registration & Authentication Flow

```
User Registration
    ↓
Generate RSA-2048 keypair
Hash password with random salt
Store in database
    ↓
User Login (Step 1)
    ↓
Hash entered password + stored salt
Compare with stored hash
    ↓
Generate 6-digit OTP
Send via email
    ↓
User Verify OTP (Step 2)
    ↓
Check OTP validity & expiry
Create authenticated session
    ↓
✓ USER LOGGED IN
```

### 2. Data Encryption

```
Creating Itinerary:
    Generate AES-256 key
    Encrypt flight details: "Flight AF123..." → "gAAAAABl2kP8..."
    Create digital signature using private RSA key
    Store encrypted data + signature in database
    ↓
Retrieving Itinerary:
    Get encrypted data from database
    Decrypt using AES key: "gAAAAABl2kP8..." → "Flight AF123..."
    Verify signature using public RSA key
    Display to user
```

### 3. Access Control Check

```
User Action (e.g., DELETE itinerary)
    ↓
Get user role from session
Check Access Control Matrix:
  - Role: "guest"
  - Object: "itineraries"
  - Action: "delete"
  - Is "delete" in guest's itinerary permissions?
    ↓
  NO → Return 403 Forbidden
  YES → Allow action
```

---

## 🧪 Testing

### Manual Test - Complete Flow

```bash
# 1. Register
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","email":"test@example.com","password":"TestPass123","role":"traveler"}'

# 2. Confirm email (in production)
# For demo, registration is confirmed

# 3. Login
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPass123"}'

# 4. Check console for OTP (simulated email)

# 5. Verify OTP
curl -X POST http://localhost:5000/api/verify-otp \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","otp":"042857"}'

# 6. Create itinerary
curl -X POST http://localhost:5000/api/itinerary \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION_COOKIE" \
  -d '{"tripName":"Test Trip","destination":"London","startDate":"2026-05-01","endDate":"2026-05-10","flightDetails":"Flight BA456","hotelDetails":"Hilton"}'
```

---

## 🔍 Key Implementation Details

### Password Hashing (Requirement 4A)
- **Algorithm**: SHA-256
- **Salt**: 128-bit random (per user)
- **Never Stored**: Original password
- **Location**: `security_utils.py` → `hash_password()`

### Encryption (Requirement 3)
- **Symmetric**: AES-256 (Fernet) for data
- **Asymmetric**: RSA-2048 for key exchange
- **Per-Item Keys**: Each itinerary has unique AES key
- **Location**: `security_utils.py` → `encrypt_val()`, `decrypt_val()`

### Digital Signatures (Requirement 4B)
- **Algorithm**: RSA-2048 signed SHA-256 hash
- **Signature Creation**: Use user's private key
- **Signature Verification**: Use user's public key
- **Proves**: Data authenticity + integrity
- **Location**: `security_utils.py` → `create_digital_signature()`, `verify_digital_signature()`

### Access Control (Requirement 2)
- **Matrix**: 3 Subjects (Admin/Traveler/Guest) × 2 Objects (Itineraries/Bookings)
- **Enforcement**: `@require_permission()` decorator
- **Check Before**: Every protected action
- **Location**: `database.py` → `ACCESS_CONTROL_MATRIX`, `check_access()`

### Encoding (Requirement 5)
- **Base64**: Booking references for safe transmission
- **QR Codes**: 2D barcodes for itinerary sharing
- **Location**: `security_utils.py` → `base64_encode()`, `generate_qr_code()`

---

## 📋 Requirements Implementation

| Requirement | Component | Implementation | File |
|------------|-----------|----------------|------|
| 1A | Single-Factor Auth | Password hashing + verification | `app.py`, `security_utils.py` |
| 1B | Multi-Factor Auth | Email OTP (6-digit, 5 min) | `app.py`, `security_utils.py` |
| 2 | Access Control Matrix | 3×2 role-based permissions | `database.py`, `app.py` |
| 3A | Key Exchange | RSA-2048 keypair generation | `security_utils.py` |
| 3B | Encryption | AES-256 symmetric encryption | `security_utils.py` |
| 4A | Hashing with Salt | SHA-256 + random 128-bit salt | `security_utils.py` |
| 4B | Digital Signature | RSA-signed SHA-256 hashes | `security_utils.py` |
| 5A | Base64 Encoding | Safe data transmission | `security_utils.py` |
| 5B | QR Code | 2D barcode generation | `security_utils.py` |

---

## 🛠️ Troubleshooting

### MongoDB Connection Error
```
Solution: Check MONGO_URI in database.py
- Verify username/password
- Whitelist IP in MongoDB Atlas
- Check internet connection
```

### OTP Not Sending
```
Solution: In demo mode, OTP is printed to console
Check console output for: "[SIMULATED EMAIL] OTP for..."
```

### Port 5000 Already in Use
```bash
# Kill the process using port 5000
lsof -ti:5000 | xargs kill -9  # macOS/Linux
netstat -ano | findstr :5000   # Windows
```

### Session Expires Too Quickly
```python
# In app.py, adjust:
"expires_at": datetime.now() + timedelta(hours=24)  # Change 24 to desired hours
```

---

## 📦 Dependencies

```
Flask==2.3.2              # Web framework
pymongo==4.4.1            # MongoDB driver
cryptography==40.0.0      # Encryption (RSA, AES)
qrcode==7.4               # QR code generation
Pillow==10.0.0            # Image processing
python-dotenv==1.0.0      # Environment variables
certifi==2023.7.22        # SSL certificates
```

---

## 🔐 Security Best Practices Implemented

✅ **Passwords**: Never stored, only hashed with salt  
✅ **Sessions**: Secure tokens with expiry  
✅ **Encryption**: AES-256 for data at rest  
✅ **Key Exchange**: RSA-2048 for secure distribution  
✅ **Integrity**: Digital signatures prevent tampering  
✅ **Account Protection**: Lockout after 5 failed attempts  
✅ **Audit Logging**: All events logged with IP/timestamp  
✅ **NIST Compliance**: Follows SP 800-63-2 architecture  

---

## 📄 License

Educational implementation for learning security concepts. Not intended for production use.

---

## 👨‍💻 Use Cases

**Learning**: Understanding authentication, encryption, and access control  
**Teaching**: Demonstrating NIST security standards  
**Portfolio**: Showcasing security implementation skills  
**Viva Prep**: Preparing for security evaluation exams  

---

## 🎓 Educational Value

This project teaches:
- Multi-factor authentication concepts
- Role-based access control implementation
- Hybrid encryption (symmetric + asymmetric)
- Password hashing with salt
- Digital signatures for integrity
- NIST compliance requirements
- RESTful API security
- Database security design

---

## 🚀 Getting Help

1. **Check**: README.md for setup issues
2. **Review**: Code comments for explanations
3. **Test**: Use provided test cases
4. **Debug**: Check Flask console for errors

---

## ✨ Features at a Glance

| Feature | Status |
|---------|--------|
| User Registration | ✅ |
| Multi-Factor Authentication | ✅ |
| Account Lockout | ✅ |
| Role-Based Access Control | ✅ |
| AES-256 Encryption | ✅ |
| RSA-2048 Key Exchange | ✅ |
| Digital Signatures | ✅ |
| Password Hashing with Salt | ✅ |
| QR Code Sharing | ✅ |
| Base64 Encoding | ✅ |
| Audit Logging | ✅ |
| NIST Compliance | ✅ |

---

## 📝 Version

**Version**: 1.0  
**Status**: ✅ Ready for Educational Use  
**Last Updated**: January 2026  

---

## 🎉 Summary

A comprehensive security implementation demonstrating all concepts required by NIST SP 800-63-2. Perfect for learning security fundamentals or preparing for security viva evaluations.

**Start by reading Setup section → Install → Run → Explore!**

Good luck! 🔐✨
