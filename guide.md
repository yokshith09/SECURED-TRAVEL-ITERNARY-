# VIVA PREPARATION GUIDE
## Secure Travel Itinerary - Security Implementation

---

## TABLE OF CONTENTS
1. Requirements
2. Security Concepts Explained
3. Where Requirements Are Met
4. How Each Feature Works
5. Common Questions

---

# PART 1: REQUIREMENTS

## From Your PDF - Total Marks: 20

| S.No | Component | Sub-Component | Marks | Status |
|------|-----------|--------------|-------|--------|
| 1 | Authentication | Single-Factor (Password) | 1.5 | ✅ Implemented |
| 1 | Authentication | Multi-Factor (OTP) | 1.5 | ✅ Implemented |
| 2 | Authorization/Access Control | Access Control Matrix (3 subjects × 3 objects) | 1.5 | ✅ Implemented |
| 2 | Authorization/Access Control | Policy Definition & Justification | 1.5 | ✅ Implemented |
| 3 | Encryption | Key Exchange (RSA-2048) | 1.5 | ✅ Implemented |
| 3 | Encryption | Encryption & Decryption (AES-256) | 1.5 | ✅ Implemented |
| 4 | Hashing & Digital Signature | Hashing with Salt | 1.5 | ✅ Implemented |
| 4 | Hashing & Digital Signature | Digital Signature using Hash | 1.5 | ✅ Implemented |
| 5 | Encoding Techniques | Encoding Implementation (Base64 + QR) | 1 | ✅ Implemented |
| 5 | Encoding Techniques | Security Levels & Risks (Theory) | 1 | ✅ Implemented |
| 5 | Encoding Techniques | Possible Attacks (Theory) | 1 | ✅ Implemented |
| 6 | **Viva** | Total | **5** | **This is your evaluation** |

---

# PART 2: SECURITY CONCEPTS EXPLAINED

## 1. AUTHENTICATION (Requirement 1: 3 marks)

### What is Authentication?
**Authentication** = **Proving who you are** (Identity verification)

Think of it like showing your ID at airport security. The system needs to verify you are actually who you claim to be.

### Single-Factor Authentication (1.5 marks)

**Single Factor = Password Only**

#### How it works in your code:

```
USER ENTERS CREDENTIALS
           ↓
email: user@example.com
password: MyPassword123
           ↓
    SERVER CHECKS:
    1. Does this email exist in database?
    2. Is the password correct?
           ↓
    PASSWORD VERIFICATION PROCESS:
    1. Get stored password hash from database
    2. Get stored salt from database
    3. Hash the entered password WITH the same salt
    4. Compare: Hash(entered password + salt) == stored hash?
           ↓
    YES ✓ → Proceed to OTP (Multi-Factor)
    NO ✗ → Reject login, increment failed attempts
```

#### In Your Code (security_utils.py):

```python
def hash_password(password, salt=None):
    """
    Takes plain password → converts to encrypted hash
    Why salt? Makes it harder to crack (adds randomness)
    """
    if not salt:
        salt = os.urandom(16).hex()  # Generate random 128-bit salt
    
    hash_obj = hashlib.sha256((password + salt).encode()).hexdigest()
    return hash_obj, salt

def verify_password(password, salt, stored_hash):
    """
    Takes entered password → hashes it with stored salt
    Compares if it matches the stored hash
    """
    current_hash, _ = hash_password(password, salt)
    return current_hash == stored_hash
```

#### Where it's enforced (app.py):

```python
@app.route('/api/login', methods=['POST'])
def login():
    # Line: "if verify_password(password, user['salt'], user['password_hash']):"
    # This verifies the password is correct
```

### Multi-Factor Authentication (1.5 marks)

**Multi-Factor = Password + OTP (Two different factors)**

#### How it works:

```
STEP 1: PASSWORD LOGIN
user@example.com + password123
           ↓
    [If password is correct]
           ↓
STEP 2: OTP EMAIL VERIFICATION
    - System generates random 6-digit code
    - Sends to user's email
    - User must enter this code to complete login
           ↓
    [If OTP matches]
           ↓
LOGIN SUCCESSFUL
User's session is created
```

#### Why two factors?
- **Password can be guessed/cracked**
- **Email OTP can't be guessed** (it's random, 6 digits, valid only 5 minutes)
- Together = Much more secure!

#### In Your Code (security_utils.py):

```python
def generate_otp():
    """Generates 6-digit random code"""
    return str(secrets.randbelow(1000000)).zfill(6)
    # Example: 042857, 123456, 000512

def send_otp_email(recipient_email, otp_code):
    """Sends OTP to user's email"""
    # In demo: prints to console
    # In production: sends actual email
```

#### Where it's enforced (app.py):

```python
@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    # User enters OTP
    # System checks:
    # 1. Is this OTP valid?
    # 2. Is it not expired? (expires in 5 minutes)
    # 3. Does it match what we sent?
```

---

## 2. AUTHORIZATION - ACCESS CONTROL (Requirement 2: 3 marks)

### What is Authorization?
**Authorization** = **What you're allowed to do**

After proving who you are (Authentication), the system decides:
- Can you create itineraries?
- Can you delete bookings?
- Can you manage users?

### Access Control Matrix

Your system has:
- **3 SUBJECTS (Roles)**: Admin, Traveler, Guest
- **2 OBJECTS (Resources)**: Itineraries, Bookings

#### The Matrix:

```
                    ITINERARIES      BOOKINGS
Admin            [C, R, U, D, S]   [C, R, U, D, V]
Traveler         [C, R, U, D, S]   [C, R, V, -, -]
Guest            [R, -, -, -, -]   [R, -, -, -, -]

C = Create
R = Read
U = Update
D = Delete
S = Share
V = Verify
- = Not allowed
```

#### In Your Code (database.py):

```python
ACCESS_CONTROL_MATRIX = {
    "admin": {
        "itineraries": ["create", "read", "update", "delete", "share"],
        "bookings": ["create", "read", "update", "delete", "verify"]
    },
    "traveler": {
        "itineraries": ["create", "read", "update", "delete", "share"],
        "bookings": ["create", "read", "verify"]
    },
    "guest": {
        "itineraries": ["read"],
        "bookings": ["read"]
    }
}
```

#### How it's enforced (app.py):

```python
def check_access(role, object_type, action):
    """
    When user tries to delete an itinerary:
    1. Get user's role (e.g., "guest")
    2. Check: Is "delete" in guest's "itineraries" permissions?
    3. If NO → Access Denied
    4. If YES → Allow action
    """
    if role not in ACCESS_CONTROL_MATRIX:
        return False, f"Invalid role: {role}"
    
    allowed_actions = ACCESS_CONTROL_MATRIX[role][object_type]
    
    if action in allowed_actions:
        return True, "Access granted"
    else:
        return False, f"Role '{role}' cannot perform '{action}'"

@require_permission('itineraries', 'delete')
def delete_itinerary(itinerary_id):
    # This decorator checks if user has permission
    # before letting them delete
```

#### Example: Guest trying to delete itinerary

```
Guest tries: DELETE /api/itinerary/123

check_access('guest', 'itineraries', 'delete')
    ↓
Look in matrix: guest → itineraries → ["read"]
    ↓
Is "delete" in ["read"]? NO
    ↓
DENY ACCESS ✗
Return 403: "Access Denied"
```

### Policy Definition & Justification

Why these permissions?

```
ADMIN:
- Policy: "System administrator with full privileges"
- Justification: "Needs complete access for system maintenance, 
                  user support, and security auditing"
- Restrictions: "Cannot view encrypted itinerary content 
                 without proper authorization"

TRAVELER:
- Policy: "Standard user who creates and manages travel plans"
- Justification: "Needs CRUD operations on own data, 
                  can share itineraries with others"
- Restrictions: "Cannot access other users' data unless 
                 explicitly shared"

GUEST:
- Policy: "Temporary or limited access user"
- Justification: "Can view shared travel information, 
                  useful for travel companions"
- Restrictions: "Read-only access only"
```

---

## 3. ENCRYPTION (Requirement 3: 3 marks)

### What is Encryption?
**Encryption** = **Converting readable data into unreadable code using a key**

#### Example:
```
PLAIN TEXT:
Flight: AF123, Departure: 10:00 AM, Terminal 3

ENCRYPTED (using AES-256):
Zu9kL2mP8qR3xW5vH7bN2jQ1zC4dF6gY

WITHOUT THE KEY: Unreadable garbage
WITH THE KEY: Can be decrypted back to original
```

### Key Exchange Mechanism (RSA-2048)

#### What is RSA?
**RSA** = **Asymmetric encryption** (uses 2 different keys)

```
RSA KEYPAIR:
┌─────────────────────┐
│   PUBLIC KEY        │
│  (Can share freely) │  ← Used to ENCRYPT
│  (Lock on door)     │
└─────────────────────┘
         ↓
      Database
         
┌─────────────────────┐
│   PRIVATE KEY       │
│  (Keep secret)      │  ← Used to DECRYPT
│  (Key to unlock)    │
└─────────────────────┘
         ↓
      User's device (never sent to server)
```

#### In Your Code (security_utils.py):

```python
def generate_rsa_keypair():
    """Generate RSA-2048 key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # 2048 bits = very secure
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    return private_pem, public_pem
    # private_pem: Keep secret
    # public_pem: Can share freely
```

#### How it's used for key exchange:

```
SCENARIO: User wants to encrypt data

Step 1: Generate AES-256 key
    aes_key = "Tz9kL2mP8qR3xW5vH7bN2jQ1zC4dF6gY"

Step 2: Encrypt this AES key using RSA
    encrypted_aes_key = rsa_encrypt_key(aes_key, public_key)
    Result: "AkL2mP8qR3xW5vH7bN2jQ1zC4dF6gY..." (encrypted)

Step 3: Send encrypted AES key to server
    Server stores: encrypted_aes_key
    Server cannot use it without private_key

Step 4: Only the user with private_key can decrypt
    recovered_aes_key = rsa_decrypt_key(encrypted_aes_key, private_key)
```

### Encryption & Decryption (AES-256)

#### What is AES?
**AES-256** = **Symmetric encryption** (uses same key for encrypt/decrypt)

```
ADVANTAGES:
- Very fast
- Very secure
- Same key for both operations

DISADVANTAGE:
- Key must be kept secret on both sides
- That's why we use RSA to securely exchange AES keys!
```

#### In Your Code (security_utils.py):

```python
def encrypt_val(data, key):
    """Encrypt data using AES-256"""
    f = Fernet(key.encode())
    encrypted = f.encrypt(data.encode()).decode()
    return encrypted
    # Example:
    # Input: "Flight AF123"
    # Output: "gAAAAABl2kP8qR3xW5vH7bN2jQ1zC4dF6gY..."

def decrypt_val(cipher, key):
    """Decrypt data using AES-256"""
    f = Fernet(key.encode())
    decrypted = f.decrypt(cipher.encode()).decode()
    return decrypted
    # Input: "gAAAAABl2kP8qR3xW5vH7bN2jQ1zC4dF6gY..."
    # Output: "Flight AF123"
```

#### How it's used in your app (app.py):

```python
@app.route('/api/itinerary', methods=['POST'])
def create_itinerary():
    # When user creates travel itinerary
    
    # Step 1: Generate unique AES key for this itinerary
    aes_key = generate_aes_key()
    
    # Step 2: Encrypt sensitive flight details
    encrypted_flight = encrypt_val(data['flightDetails'], aes_key)
    # Original: "Flight AF123, Departure 10:00 AM, Terminal 3"
    # Encrypted: "gAAAAABl2kP8qR3..."
    
    encrypted_hotel = encrypt_val(data['hotelDetails'], aes_key)
    
    # Step 3: Store in database
    itinerary_doc = {
        "flightDetails": encrypted_flight,  # Stored encrypted!
        "hotelDetails": encrypted_hotel,    # Stored encrypted!
        "aes_key": aes_key  # Stored per-itinerary
    }
    
    itineraries_collection.insert_one(itinerary_doc)

@app.route('/api/my_itineraries', methods=['GET'])
def get_itineraries():
    # When user retrieves itineraries
    
    # Step 1: Get encrypted data from database
    decrypted = {
        # Step 2: Decrypt using AES key
        "flightDetails": decrypt_val(itin['flightDetails'], itin['aes_key']),
        # Decrypted: "Flight AF123, Departure 10:00 AM, Terminal 3"
    }
```

#### Why is this secure?

```
SCENARIO 1: Hacker gets database
    Database contains: encrypted flight details
    Hacker tries to read: "gAAAAABl2kP8qR3..."
    Result: UNREADABLE without AES key ✓

SCENARIO 2: Hacker steals AES key
    Hacker has: AES key
    Hacker needs: Private RSA key to use it
    Result: CANNOT USE KEY without private key ✓

SCENARIO 3: Legitimate user retrieves
    User has: AES key + Data
    User can: Decrypt → View readable flight details ✓
```

---

## 4. HASHING & DIGITAL SIGNATURE (Requirement 4: 3 marks)

### Hashing with Salt

#### What is Hashing?
**Hashing** = **Converting data into fixed-length code that CANNOT be reversed**

```
ENCRYPTION vs HASHING:

ENCRYPTION:
data → [encrypt] → encrypted code → [decrypt] → data
Can reverse it back!

HASHING:
data → [hash] → hash code
CANNOT reverse it! One-way process.

Example:
"password123" → SHA-256 → "a1b2c3d4e5f6..."
"password123" → SHA-256 → SAME "a1b2c3d4e5f6..."
"password456" → SHA-256 → DIFFERENT "z9y8x7w6v5u4..."
```

#### Why use salt?

```
WITHOUT SALT:
password "123456" 
    → SHA-256 → always produces same hash
    
If hacker knows hash of "123456", they recognize it!

WITH SALT:
password "123456" + salt "abc123"
    → SHA-256 → "u9kL2mP8qR3..."
    
Even if hacker cracks password, they need to do it 
for EVERY DIFFERENT SALT (computational nightmare!)
```

#### In Your Code (security_utils.py):

```python
def hash_password(password, salt=None):
    """
    Creates IRREVERSIBLE hash of password
    """
    if not salt:
        salt = os.urandom(16).hex()  # Random 128-bit salt
    
    # Combine password + salt, then hash
    hash_obj = hashlib.sha256((password + salt).encode()).hexdigest()
    return hash_obj, salt
    
# Example:
# password: "TravelPass123"
# salt: "a7f3b2d9e1c4k6m8"
# combined: "TravelPass123a7f3b2d9e1c4k6m8"
# hash: "9f8c7e5d3b1a9f8e7d6c5b4a3f2e1d0c"
```

#### Where it's used (app.py):

```python
@app.route('/api/register', methods=['POST'])
def register():
    password = data['password']
    
    # Hash password with salt before storing
    hashed_pw, salt = hash_password(password)
    
    # Store ONLY the hash and salt
    user_doc = {
        "password_hash": hashed_pw,  # Hash, NOT original password
        "salt": salt,  # Random salt
        # Original password is NEVER stored ✓
    }
    
    users_collection.insert_one(user_doc)

@app.route('/api/login', methods=['POST'])
def login():
    entered_password = data['password']
    user = users_collection.find_one({"email": email})
    
    # Verify by hashing entered password with stored salt
    if verify_password(entered_password, user['salt'], user['password_hash']):
        # Passwords match! (without ever knowing original)
        print("Login successful")
```

### Digital Signature Using Hash

#### What is a Digital Signature?
**Digital Signature** = **Proof that data wasn't tampered with AND was signed by a specific person**

```
Real-world analogy:
- You sign a document with your unique signature
- Everyone can see you signed it
- But they can't forge your signature
- If document is changed, signature becomes invalid

Digital version:
- Data → [hash] → [encrypt with private RSA key] → signature
- Anyone can → [decrypt with public key] → verify signature
- Only YOU can create it (have private key)
- If data changes → signature won't match
```

#### In Your Code (security_utils.py):

```python
def create_digital_signature(data, private_pem):
    """
    Creates unique signature for data
    Proves: "This data was signed by person with this private key"
    """
    # Step 1: Hash the data
    message_hash = hashlib.sha256(data.encode()).digest()
    
    # Step 2: Encrypt the hash with private key
    signature = private_key.sign(
        message_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return base64.b64encode(signature).decode()
    # Output: Base64-encoded signature

def verify_digital_signature(data, signature_b64, public_pem):
    """
    Verifies signature without private key!
    Proves: "Data wasn't tampered with"
    """
    # Anyone can verify using public key
    public_key.verify(
        signature,
        message_hash,
        padding.PSS(...),
        hashes.SHA256()
    )
    
    return True  # Valid
```

#### How it's used (app.py):

```python
# CREATING ITINERARY
@app.route('/api/itinerary', methods=['POST'])
def create_itinerary():
    user = users_collection.find_one({"email": session['user']['email']})
    
    # Step 1: Prepare data to sign
    itinerary_data = json.dumps({
        "tripName": data['tripName'],
        "destination": data['destination'],
        "startDate": data['startDate'],
        "endDate": data['endDate']
    }, sort_keys=True)
    
    # Step 2: Create signature using private key
    signature = create_digital_signature(itinerary_data, user['rsa_private_key'])
    
    # Step 3: Store itinerary WITH signature
    itinerary_doc = {
        "tripName": data['tripName'],
        ...
        "signature": signature  # Include signature
    }

# VERIFYING ITINERARY
@app.route('/api/itinerary/<itinerary_id>/verify', methods=['GET'])
def verify_itinerary_signature(itinerary_id):
    itin = itineraries_collection.find_one({"_id": ObjectId(itinerary_id)})
    owner = users_collection.find_one({"email": itin['owner']})
    
    # Reconstruct original data
    original_data = json.dumps({
        "tripName": itin['tripName'],
        "destination": itin['destination'],
        ...
    }, sort_keys=True)
    
    # Verify signature using public key
    is_valid = verify_digital_signature(
        original_data, 
        itin['signature'], 
        owner['rsa_public_key']  # Public key, safe to share!
    )
    
    if is_valid:
        return "Data is authentic and wasn't tampered with" ✓
    else:
        return "DANGER: Data was modified!" ✗
```

#### Security guarantees:

```
SCENARIO: Hacker modifies flight details in database

BEFORE:
Original data: "Flight AF123, 10:00 AM"
Signature: "9f8c7e5d3b1a..."

HACKER MODIFIES:
New data: "Flight AF999, 5:00 PM"

VERIFICATION:
1. Hash new data → "x9k2L1m0P9qR3..."
2. Decrypt signature with public key → "9f8c7e5d3b1a..."
3. Compare hashes:
   "x9k2L1m0P9qR3..." ≠ "9f8c7e5d3b1a..."
   ↓
   SIGNATURE INVALID ✗
   TAMPERING DETECTED!
```

---

## 5. ENCODING TECHNIQUES (Requirement 5: 3 marks)

### What is Encoding?
**Encoding** = **Converting data into different format for transmission/storage**

**IMPORTANT**: Encoding ≠ Encryption
- Encoding: Reversible, no key needed, NOT secure
- Encryption: Encrypted, key needed, VERY secure

### Base64 Encoding

#### What is Base64?
Converts binary data into 64 safe ASCII characters.

```
WHY?
- Some systems only understand text (not binary)
- Email protocols were designed for text
- Easier to transmit/display binary data as text

HOW IT WORKS:
Original: "Hi"
Binary: 01001000 01101001
Base64: "SGk="

Base64 alphabet: A-Z a-z 0-9 + / =
(64 characters, hence "Base64")
```

#### In Your Code (security_utils.py):

```python
def base64_encode(data):
    """Convert data to Base64"""
    return base64.b64encode(data.encode()).decode()
    
# Example:
# Input: "Flight AF123"
# Output: "Rmxpghb0hAGY3="

def base64_decode(encoded_data):
    """Convert Base64 back to original"""
    return base64.b64decode(encoded_data).decode()
    
# Input: "Rmxpghb0hAGY3="
# Output: "Flight AF123"
```

#### How it's used (app.py):

```python
# When creating booking
encoded_reference = base64_encode(data['booking_reference'])
# Original: "BK-2026-12345"
# Encoded: "QkstMjAyNi0xMjM0NQ=="

booking_doc = {
    "booking_reference": data['booking_reference'],
    "encoded_reference": encoded_reference,  # For display/sharing
}
```

#### Security Analysis:

```
SECURITY LEVEL: LOW (Not secure!)

WHY:
- Base64 is EASILY reversible
- Anyone can decode it: "QkstMjAyNi0xMjM0NQ==" → "BK-2026-12345"
- No encryption involved
- Provides NO confidentiality

USE CASES:
✓ Encoding data for JSON transmission (data transport)
✓ Encoding binary data in emails
✓ Making data URL-safe

DO NOT USE FOR:
✗ Protecting sensitive data
✗ Passwords
✗ Financial information
```

### QR Code Generation

#### What is QR Code?
**QR Code** = **2D barcode containing data** that smartphone cameras can read

```
EXAMPLE:
┌─────────────────┐
│ ░░░░░░░░░░░░░░░│
│ ░  ▄▄▄  ░░░  ░ │
│ ░ ▐███▌ ░▓░ ░  │
│ ░  ▀▀▀  ░░░░░░ │
│ ░░░░░░░░░░░░░░░│
└─────────────────┘

Scan it → Contains data
Data could be: URL, text, contact, WiFi, etc.
```

#### In Your Code (security_utils.py):

```python
def generate_qr_code(data):
    """Generate QR code from data"""
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
```

#### How it's used (app.py):

```python
# When creating itinerary
qr_data = f"""
TRAVEL ITINERARY
================
Trip: Paris Summer 2026
Destination: Paris, France
Travel Dates: 2026-06-01 to 2026-06-30

FLIGHT DETAILS:
Flight AF123, Departure 10:00 AM, Terminal 3

HOTEL DETAILS:
Hotel Royale, Booking Ref: ABC123
"""

qr_code = generate_qr_code(qr_data)
# Returns: "data:image/png;base64,iVBORw0KG..."
```

#### Security Analysis:

```
SECURITY LEVEL: LOW (Not secure!)

ADVANTAGES:
✓ Easy to scan with smartphone
✓ Can contain up to 4000 characters
✓ Works offline (no internet needed)

DISADVANTAGES:
✗ Data is visible to anyone who scans
✗ No encryption
✗ Can be intercepted/photographed
✗ Potential for malicious QR codes (phishing)

RISKS:
- User scans fake QR code → redirected to malicious site
- User photographed scanning QR → data visible in image
- QR code contains unencrypted personal information

MITIGATION IN YOUR APP:
✓ QR contains readable itinerary (not encrypted)
✓ But itinerary is encrypted in DATABASE
✓ QR used for easy sharing only
✓ Original data remains secure
```

### Possible Attacks

#### 1. Base64 Injection
```
Attacker: Sends malicious Base64-encoded data
Example: "PGltYWdlIHNyYz1qYXZhc2NyaXB0Oj4=" 
         (Decodes to: "<image src=javascript:>")

Protection:
- Validate input after decoding
- Use parameterized queries
- Never execute decoded data
```

#### 2. QR Phishing
```
Attacker: Creates QR code pointing to malicious site
         QR looks legitimate but links to fake website

Protection:
- Always verify URL before scanning
- Use HTTPS for sensitive links
- Display full URL to user before redirecting
```

#### 3. Man-in-the-Middle
```
Attacker: Intercepts encoded data in transit
         Modifies Base64/QR code

Protection:
- Use HTTPS/TLS for transmission
- Verify digital signatures of data
- Use encryption alongside encoding
```

#### 4. Social Engineering
```
Attacker: User scans QR code from attacker
         Leads to credential harvesting page

Protection:
- User awareness training
- Verify source of QR codes
- Use short expiry times for codes
```

---

# PART 3: WHERE REQUIREMENTS ARE MET

## Quick Reference Table

| Requirement | Location in Code | Key Lines/Functions |
|------------|-----------------|-------------------|
| **Req 1A: Single-Factor Auth** | security_utils.py + app.py | `hash_password()`, `verify_password()`, `/api/login` |
| **Req 1B: Multi-Factor Auth** | security_utils.py + app.py | `generate_otp()`, `send_otp_email()`, `/api/verify-otp` |
| **Req 2A: Access Control Matrix** | database.py | `ACCESS_CONTROL_MATRIX` (lines 40-52) |
| **Req 2B: Policy Definition** | database.py | `ACCESS_POLICIES` (lines 54-72) |
| **Req 2C: AC Implementation** | app.py | `require_permission()` decorator, `check_access()` |
| **Req 3A: Key Exchange (RSA)** | security_utils.py | `generate_rsa_keypair()`, `rsa_encrypt_key()`, `rsa_decrypt_key()` |
| **Req 3B: Encryption (AES)** | security_utils.py | `generate_aes_key()`, `encrypt_val()`, `decrypt_val()` |
| **Req 4A: Hashing with Salt** | security_utils.py | `hash_password()` |
| **Req 4B: Digital Signature** | security_utils.py | `create_digital_signature()`, `verify_digital_signature()` |
| **Req 5A: Encoding (Base64)** | security_utils.py | `base64_encode()`, `base64_decode()` |
| **Req 5B: Encoding (QR Code)** | security_utils.py | `generate_qr_code()` |
| **Req 5C: Security Analysis** | security_utils.py | `analyze_encoding_security()` |

---

# PART 4: FLOWCHARTS & WORKFLOWS

## Complete User Registration & Login Flow

```
┌─────────────────┐
│ USER REGISTERS  │
│ (index.html)    │
└────────┬────────┘
         │
         ↓
    /api/register (POST)
    {name, email, password, role}
         │
         ↓
    ┌────────────────────────────┐
    │ 1. Validate Input          │
    │ 2. Check if user exists    │
    │ 3. Validate password (8+)  │
    └────────┬───────────────────┘
             │
             ↓
    ┌────────────────────────────┐
    │ Generate RSA Keypair       │
    │ (Req 3A - Key Exchange)    │
    │ public_key, private_key    │
    └────────┬───────────────────┘
             │
             ↓
    ┌────────────────────────────┐
    │ Hash Password with Salt    │
    │ (Req 4A - Hashing)         │
    │ salt = random 128-bit      │
    │ hash = SHA256(pass + salt) │
    └────────┬───────────────────┘
             │
             ↓
    ┌────────────────────────────┐
    │ Store in Database:         │
    │ - password_hash            │
    │ - salt                     │
    │ - rsa_private_key          │
    │ - rsa_public_key           │
    └────────┬───────────────────┘
             │
             ↓
    ✓ Registration Success
         │
         ↓
┌─────────────────┐
│ USER LOGS IN    │
│ (index.html)    │
└────────┬────────┘
         │
         ↓
    /api/login (POST)
    {email, password}
         │
         ↓
    ┌────────────────────────────┐
    │ STEP 1: Password Check     │
    │ (Req 1A - Single Factor)   │
    │ 1. Retrieve user from DB   │
    │ 2. Get stored salt         │
    │ 3. Hash entered password   │
    │    hash(password + salt)   │
    │ 4. Compare with stored     │
    └────────┬───────────────────┘
             │
             ├─→ WRONG? → Increment failed attempts
             │            (Max 5) → Lock account
             │
             ├─→ CORRECT? ↓
             │
    ┌────────────────────────────┐
    │ STEP 2: OTP Generation     │
    │ (Req 1B - Multi Factor)    │
    │ 1. Generate 6-digit OTP    │
    │ 2. Store in OTP collection │
    │    (expires in 5 min)      │
    │ 3. Send to email           │
    │ 4. Show OTP form to user   │
    └────────┬───────────────────┘
             │
             ↓
    /api/verify-otp (POST)
    {email, otp}
         │
         ↓
    ┌────────────────────────────┐
    │ Verify OTP                 │
    │ 1. Get OTP record from DB  │
    │ 2. Check if expired        │
    │ 3. Compare entered OTP     │
    │ 4. Mark as verified        │
    └────────┬───────────────────┘
             │
             ├─→ INVALID? → Show error
             │
             ├─→ EXPIRED? → Ask user to login again
             │
             ├─→ VALID? ↓
             │
    ┌────────────────────────────┐
    │ Create Session             │
    │ - Store user in session    │
    │ - Set session cookies      │
    │ - Redirect to dashboard    │
    └────────┬───────────────────┘
             │
             ↓
    ✓ Login Success
    User can now access protected resources
```

## Creating Encrypted Itinerary

```
┌──────────────────────────┐
│ USER CREATES ITINERARY   │
│ (dashboard.html form)    │
└───────┬──────────────────┘
        │
        ↓
   /api/itinerary (POST)
   {tripName, destination, 
    startDate, endDate,
    flightDetails, hotelDetails}
        │
        ↓
   ┌────────────────────────────────┐
   │ STEP 1: Generate AES Key       │
   │ (Req 3A - Key Exchange)        │
   │ aes_key = random 256-bit       │
   └────────┬─────────────────────┘
            │
            ↓
   ┌────────────────────────────────┐
   │ STEP 2: Encrypt Sensitive Data │
   │ (Req 3B - Encryption)          │
   │                                │
   │ encrypted_flight =             │
   │   encrypt_val(                 │
   │     flightDetails,             │
   │     aes_key                    │
   │   )                            │
   │                                │
   │ encrypted_hotel =              │
   │   encrypt_val(                 │
   │     hotelDetails,              │
   │     aes_key                    │
   │   )                            │
   └────────┬─────────────────────┘
            │
            ↓
   ┌────────────────────────────────┐
   │ STEP 3: Create Digital         │
   │ Signature (Req 4B)             │
   │                                │
   │ data_to_sign = {               │
   │   "tripName": ...,             │
   │   "destination": ...,          │
   │   "startDate": ...,            │
   │   "endDate": ...               │
   │ }                              │
   │                                │
   │ signature =                    │
   │   create_digital_signature(    │
   │     data_to_sign,              │
   │     user_private_key           │
   │   )                            │
   └────────┬─────────────────────┘
            │
            ↓
   ┌────────────────────────────────┐
   │ STEP 4: Generate QR Code       │
   │ (Req 5B - Encoding)            │
   │                                │
   │ qr_data = formatted            │
   │   itinerary text               │
   │                                │
   │ qr_code =                      │
   │   generate_qr_code(qr_data)    │
   │                                │
   │ Returns: Base64 PNG image      │
   └────────┬─────────────────────┘
            │
            ↓
   ┌────────────────────────────────┐
   │ STEP 5: Store in Database      │
   │                                │
   │ itinerary_doc = {              │
   │   "tripName": ...,             │
   │   "destination": ...,          │
   │   "flightDetails":encrypted,   │
   │   "hotelDetails": encrypted,   │
   │   "aes_key": aes_key,          │
   │   "signature": signature,      │
   │   "owner": user@email,         │
   │   "created_at": timestamp      │
   │ }                              │
   │                                │
   │ db.insert(itinerary_doc)       │
   └────────┬─────────────────────┘
            │
            ↓
   ✓ Itinerary Created
   - Data encrypted ✓
   - Signature created ✓
   - QR code generated ✓
```

## Retrieving & Verifying Itinerary

```
┌───────────────────────────┐
│ USER VIEWS ITINERARIES    │
│ (dashboard - My tab)      │
└──────┬────────────────────┘
       │
       ↓
  /api/my_itineraries (GET)
       │
       ↓
  ┌─────────────────────────────────┐
  │ STEP 1: Access Control Check    │
  │ (Req 2C - Authorization)        │
  │                                 │
  │ role = "traveler"               │
  │ check_access(                   │
  │   "traveler",                   │
  │   "itineraries",                │
  │   "read"                        │
  │ )                               │
  │                                 │
  │ Is "read" in permissions? YES ✓ │
  └──────┬────────────────────────┘
         │
         ↓
  ┌──────────────────────────────────┐
  │ STEP 2: Fetch from Database      │
  │                                  │
  │ Get all itineraries where:       │
  │ - owner == user email OR         │
  │ - user in shared_with list      │
  └──────┬──────────────────────────┘
         │
         ↓
  ┌──────────────────────────────────┐
  │ STEP 3: Decrypt Data             │
  │ (Req 3B - Decryption)            │
  │                                  │
  │ flightDetails =                  │
  │   decrypt_val(                   │
  │     encrypted_flight,            │
  │     aes_key                      │
  │   )                              │
  │ Returns: readable flight text    │
  │                                  │
  │ hotelDetails =                   │
  │   decrypt_val(                   │
  │     encrypted_hotel,             │
  │     aes_key                      │
  │   )                              │
  │ Returns: readable hotel text     │
  └──────┬──────────────────────────┘
         │
         ↓
  ┌──────────────────────────────────┐
  │ STEP 4: Return to User           │
  │                                  │
  │ Response includes:               │
  │ - tripName                       │
  │ - destination                    │
  │ - flightDetails (decrypted)      │
  │ - hotelDetails (decrypted)       │
  │ - owner, created_at              │
  │ - can_edit, can_delete, can_share│
  └──────┬──────────────────────────┘
         │
         ↓
  ✓ Itineraries displayed to user
  
  ┌──────────────────────────────────┐
  │ USER VERIFIES SIGNATURE          │
  │ (Click "Verify Signature" btn)   │
  └──────┬──────────────────────────┘
         │
         ↓
  /api/itinerary/<id>/verify (GET)
         │
         ↓
  ┌──────────────────────────────────┐
  │ STEP 1: Get Original Data        │
  │                                  │
  │ Reconstruct exact JSON:          │
  │ {                                │
  │   "tripName": ...,               │
  │   "destination": ...,            │
  │   "startDate": ...,              │
  │   "endDate": ...,                │
  │ }                                │
  │ (MUST be identical to creation)  │
  └──────┬──────────────────────────┘
         │
         ↓
  ┌──────────────────────────────────┐
  │ STEP 2: Verify Signature         │
  │ (Req 4B - Digital Signature)     │
  │                                  │
  │ verify_digital_signature(        │
  │   original_data,                 │
  │   stored_signature,              │
  │   owner_public_key               │
  │ )                                │
  │                                  │
  │ Checks:                          │
  │ 1. Hash original data            │
  │ 2. Decrypt signature with        │
  │    public key                    │
  │ 3. Compare hashes                │
  └──────┬──────────────────────────┘
         │
         ├─→ Hashes MATCH → Signature Valid ✓
         │   "Data integrity confirmed"
         │
         └─→ Hashes DON'T MATCH → Tampered ✗
             "DANGER: Data was modified!"
```

---

# PART 5: COMMON VIVA QUESTIONS & ANSWERS

## Authentication Questions

### Q1: What is the difference between Authentication and Authorization?

**Authentication** = **IDENTIFICATION** (Who are you?)
- Proves user identity
- Single-Factor: Password only
- Multi-Factor: Password + OTP
- Examples: Login, face recognition

**Authorization** = **PERMISSION** (What can you do?)
- Decides what authenticated user can do
- Access control matrix
- Role-based permissions
- Examples: Can user delete? Can user edit?

### Q2: Why do we need Multi-Factor Authentication?

**Single password alone is NOT secure because:**
1. User might choose weak password
2. Password can be guessed/brute forced
3. Password can be stolen from public WiFi (if not HTTPS)
4. User might reuse password on other sites

**With MFA (Password + OTP):**
- Even if password is stolen, OTP is generated fresh each time
- OTP is random 6-digit code
- OTP expires in 5 minutes (limited time window)
- Attacker needs BOTH password AND access to email
- Security greatly improved!

### Q3: Explain how your password hashing works

**Without salt:**
```
Password: "123456"
Hash (SHA-256): "a1b2c3d4e5f6..."

If hacker knows this hash, they can recognize password
```

**With salt (your implementation):**
```
Password: "123456"
Salt: "a7f3b2d9e1c4k6m8" (random, per user)
Hash: SHA256("123456" + "a7f3b2d9e1c4k6m8") = "9f8c7e5d3b1a..."

Even if hacker cracks hash for one user,
the salt is different for each user!
This makes cracking EVERY password extremely difficult.
```

### Q4: Where is the password stored in your app?

**Answer:**
- Original password: **NEVER stored** ✓
- Password hash: Stored in database ✓
- Salt: Stored in database ✓

```
Database stores:
{
  "email": "user@example.com",
  "password_hash": "9f8c7e5d3b1a...",
  "salt": "a7f3b2d9e1c4k6m8"
}

Original password only known to user!
```

## Authorization Questions

### Q5: Explain your Access Control Matrix

**3 Subjects (Roles):**
1. **Admin** - System administrator
2. **Traveler** - Regular user
3. **Guest** - Limited user

**2 Objects (Resources):**
1. **Itineraries** - Travel plans
2. **Bookings** - Flight/hotel bookings

**Permissions:**

```
Matrix:
                    ITINERARIES      BOOKINGS
Admin            [C, R, U, D, S]   [C, R, U, D, V]
Traveler         [C, R, U, D, S]   [C, R, V]
Guest            [R]               [R]

C = Create
R = Read
U = Update
D = Delete
S = Share
V = Verify
```

### Q6: Why is Access Control important?

**Without Access Control:**
- Guest user could delete anyone's itinerary
- Traveler could change other user's bookings
- Anyone could view sensitive data
- System has no security!

**With Access Control:**
- Guest can only READ
- Traveler can CREATE, READ, UPDATE, DELETE, SHARE own data
- Admin can do everything
- Data is protected from unauthorized access

### Q7: How do you enforce Access Control in your code?

**Using @require_permission decorator:**

```python
@require_permission('itineraries', 'delete')
def delete_itinerary(itinerary_id):
    # This function can only be called by users
    # who have 'delete' permission on 'itineraries'
    # Others get 403 Forbidden error
```

**Behind the scenes:**
```
1. User tries: DELETE /api/itinerary/123
2. Decorator checks:
   - role = session['user']['role']
   - allowed_actions = ACCESS_CONTROL_MATRIX[role]['itineraries']
   - Is 'delete' in allowed_actions?
3. NO → Return 403 Forbidden
4. YES → Allow delete operation
```

## Encryption Questions

### Q8: Why do we need RSA if we have AES?

**AES (Symmetric):**
- Pro: Very fast, very secure
- Con: Same key for encrypt/decrypt, key must be kept secret on BOTH sides

**RSA (Asymmetric):**
- Pro: Two different keys (public + private)
- Con: Much slower than AES

**Solution: Hybrid Encryption**
```
1. Use AES for actual data encryption (fast)
2. Use RSA to securely exchange AES keys (secure)

Example in your app:
- Generate AES key for itinerary
- Use AES to encrypt flight details (fast)
- Use RSA to encrypt AES key (secure distribution)
```

### Q9: Explain key generation and storage

**RSA Keypair Generation:**
```python
private_key, public_key = generate_rsa_keypair()
```

**Storage:**
```
Database stores:
{
  "email": "user@example.com",
  "rsa_private_key": "-----BEGIN PRIVATE KEY-----\n...",
  "rsa_public_key": "-----BEGIN PUBLIC KEY-----\n..."
}

Private key: MUST be kept secret ✓
Public key: Can be shared freely ✓
```

**This enables:**
- User A can encrypt with User B's public key
- User B can decrypt with their private key
- Only User B can decrypt (only they have private key)

### Q10: How does AES encryption work in your itinerary?

**When creating:**
```
1. Generate unique AES key: aes_key = "Tz9kL2mP8qR3xW5vH7bN2jQ1zC4dF6gY"

2. Encrypt flight details:
   Original: "Flight AF123, 10:00 AM, Terminal 3"
   encrypted_flight = encrypt_val(original, aes_key)
   Result: "gAAAAABl2kP8qR3xW5vH7bN2jQ1zC4dF6gY..."

3. Store encrypted data:
   itinerary_doc = {
     "flightDetails": "gAAAAABl2kP8qR3...",
     "aes_key": aes_key
   }

4. Database stores encrypted data!
```

**When retrieving:**
```
1. Get encrypted data from database:
   "gAAAAABl2kP8qR3xW5vH7bN2jQ1zC4dF6gY..."

2. Get AES key:
   "Tz9kL2mP8qR3xW5vH7bN2jQ1zC4dF6gY"

3. Decrypt:
   decrypted_flight = decrypt_val(encrypted, aes_key)
   Result: "Flight AF123, 10:00 AM, Terminal 3"

4. Display to user!
```

## Digital Signature Questions

### Q11: What is a Digital Signature and why use it?

**Digital Signature = Proof of authorship + authenticity**

**Example: Document signing**
```
Real world:
- You sign document with unique signature
- Everyone sees you signed it
- Can't forge your signature
- If document changes, signature becomes invalid

Digital version:
- Data → Hash → Sign with private key → Signature
- Anyone can → Verify with public key
- Proof you created it + Data wasn't tampered
```

### Q12: How do you create and verify signatures in your app?

**Creating signature:**
```python
# When creating itinerary
itinerary_data = json.dumps({
    "tripName": "Paris Summer",
    "destination": "Paris",
    "startDate": "2026-06-01",
    "endDate": "2026-06-30"
}, sort_keys=True)

signature = create_digital_signature(itinerary_data, private_key)
# Result: "9f8c7e5d3b1a..." (base64 encoded)

# Store with itinerary
itinerary_doc = {
    ...data...,
    "signature": signature
}
```

**Verifying signature:**
```python
# When user clicks "Verify Signature"
original_data = json.dumps({
    "tripName": "Paris Summer",
    "destination": "Paris",
    "startDate": "2026-06-01",
    "endDate": "2026-06-30"
}, sort_keys=True)

is_valid = verify_digital_signature(
    original_data,
    stored_signature,
    owner_public_key
)

if is_valid:
    print("✓ Data is authentic!")
else:
    print("✗ Data was tampered with!")
```

### Q13: What happens if someone modifies the itinerary?

```
SCENARIO: Hacker modifies flight details

ORIGINAL:
{
  "tripName": "Paris Summer",
  "destination": "Paris",
  "startDate": "2026-06-01",
  "endDate": "2026-06-30",
  "signature": "9f8c7e5d3b1a..."
}

HACKER CHANGES destination to "London":
{
  "tripName": "Paris Summer",
  "destination": "London",  ← MODIFIED!
  "startDate": "2026-06-01",
  "endDate": "2026-06-30",
  "signature": "9f8c7e5d3b1a..."  ← Same signature
}

VERIFICATION FAILS:
1. Hash modified data → "a1b2c3d4e5f6..."
2. Decrypt signature with public key → "9f8c7e5d3b1a..."
3. Compare: "a1b2c3d4e5f6..." ≠ "9f8c7e5d3b1a..."
           ↓
   SIGNATURE INVALID! ✗
   TAMPERING DETECTED!
```

## Encoding Questions

### Q14: Why is Base64 not secure?

**Base64 is ENCODING, not ENCRYPTION:**

```
Base64 is easily reversible:
"QkstMjAyNi0xMjM0NQ==" → "BK-2026-12345"

Anyone can decode it!
```

**Use Base64 for:**
✓ Data transport (JSON transmission)
✓ Storing binary in text format
✓ Making data URL-safe

**Do NOT use for:**
✗ Protecting sensitive data
✗ Passwords
✗ Financial information

### Q15: What is a QR Code and how do you use it?

**QR Code = 2D barcode containing data**

**In your app:**
```
1. User creates itinerary
2. System generates QR code with itinerary details
3. QR code displayed to user
4. User can:
   - Screenshot and share
   - Print and give to travel companion
   - Share via messaging app

5. Someone scans QR code
   → Shows readable itinerary details
   → But ORIGINAL data is still encrypted in database!
```

**Security:**
- QR contains readable text (for easy sharing)
- Actual database stores encrypted data
- Best of both worlds: Convenience + Security

### Q16: What are the risks of QR codes?

**Risk 1: Malicious QR codes (Phishing)**
```
Attacker: Creates QR code pointing to malicious site
Result: User scans → redirected to fake website
Prevention: Always verify URL before clicking
```

**Risk 2: Visible to anyone**
```
If you screenshot QR code and upload online,
anyone can scan it and see the data
Prevention: Use privacy settings when sharing
```

**Risk 3: Intercepted data**
```
Data in QR is not encrypted
If QR is intercepted, data is readable
Prevention: Encrypt data before putting in QR
(Your app does this - QR contains readable text,
but DB stores encrypted version)
```

## System Design Questions

### Q17: Explain the overall security architecture

**Your system uses LAYERED SECURITY:**

**Layer 1: Authentication**
- Single-factor: Password (Req 1A)
- Multi-factor: OTP email (Req 1B)
- Prevents unauthorized access

**Layer 2: Authorization**
- Access Control Matrix (Req 2)
- Role-based permissions
- Limits what users can do

**Layer 3: Encryption**
- Data at rest: AES-256 (Req 3B)
- Key exchange: RSA-2048 (Req 3A)
- Protects data confidentiality

**Layer 4: Integrity**
- Hashing with salt (Req 4A)
- Digital signatures (Req 4B)
- Prevents tampering

**Layer 5: Encoding**
- Base64 (Req 5A)
- QR codes (Req 5B)
- Easy data sharing

### Q18: How does your application ensure NIST SP 800-63-2 compliance?

**NIST SP 800-63-2 = E-Authentication Architecture**

**Requirement 1: Credential Management**
✓ Passwords hashed with salt (Req 4A)
✓ Password validation on registration (min 8 chars)
✓ Account lockout after 5 failed attempts

**Requirement 2: Assertion & Cryptographic Key Management**
✓ Multi-factor authentication implemented (Req 1B)
✓ RSA-2048 keypair generation (Req 3A)
✓ AES-256 encryption (Req 3B)

**Requirement 3: Cryptographic Algorithms**
✓ SHA-256 for hashing (Req 4A)
✓ RSA-2048 for asymmetric crypto (Req 3A)
✓ AES-256-GCM for symmetric crypto (Req 3B)

**Requirement 4: Access Control**
✓ Role-based access control (Req 2)
✓ Least privilege principle
✓ Audit logging

---

# FINAL TIPS FOR YOUR VIVA

## Things Examiners Will Look For

### 1. Understanding (Most Important)
- Can you EXPLAIN concepts in your own words?
- Can you answer "WHY" not just "WHAT"?
- Can you connect requirements to code locations?

### 2. Code Knowledge
- Can you point to specific code lines for each requirement?
- Can you trace execution flow?
- Can you explain what each function does?

### 3. Security Awareness
- Understand threats and mitigations
- Know when to use what technique
- Understand limitations and tradeoffs

### 4. Design Decisions
- Why AES for data + RSA for keys?
- Why both encryption and digital signature?
- Why hash passwords with salt?

## Things That Impress

1. **Explaining the "Why"**: "We use RSA for key exchange because... and AES for encryption because..."

2. **Pointing to Code**: "Let me show you the implementation in app.py line 245..."

3. **Connecting Concepts**: "Encryption protects confidentiality, digital signatures protect integrity..."

4. **Understanding Threats**: "An attacker could... but our system prevents this by..."

5. **Knowing Limitations**: "Base64 is not secure because... so we also use encryption..."



# QUICK REFERENCE CHEAT SHEET

## Requirement → Code Location

| # | Requirement | File | Function/Line | What It Does |
|---|------------|------|---------------|-------------|
| 1A | Single-Factor Auth | security_utils.py | hash_password() verify_password() | Passwords with salt |
| 1B | Multi-Factor Auth | security_utils.py | generate_otp() send_otp_email() | Email OTP |
| 2 | Access Control | database.py | ACCESS_CONTROL_MATRIX | 3×2 permission matrix |
| 2 | Policy Definition | database.py | ACCESS_POLICIES | Why each role exists |
| 2 | AC Enforcement | app.py | require_permission() | Decorator to check permissions |
| 3A | Key Exchange | security_utils.py | generate_rsa_keypair() rsa_encrypt_key() | RSA-2048 keys |
| 3B | Encryption | security_utils.py | encrypt_val() decrypt_val() | AES-256 encryption |
| 4A | Hashing + Salt | security_utils.py | hash_password() | SHA-256 with salt |
| 4B | Digital Signature | security_utils.py | create_digital_signature() verify_digital_signature() | RSA signatures |
| 5A | Base64 Encoding | security_utils.py | base64_encode() base64_decode() | Base64 codec |
| 5B | QR Code | security_utils.py | generate_qr_code() | QR code generation |
| 5C | Security Analysis | security_utils.py | analyze_encoding_security() | Theory & risks |

---
   
