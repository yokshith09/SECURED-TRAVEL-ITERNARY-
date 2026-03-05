from pymongo import MongoClient
import certifi
import os
from datetime import datetime

# ============================================================================
# SECURE DATABASE CONNECTION (NIST Compliant)
# ============================================================================
# IMPORTANT: In production, use environment variables
# For development/demo, you can use the hardcoded URI below

MONGO_URI = os.getenv('MONGO_URI', 
    "Paste your MongoDb url here "
)

# Use certifi for SSL certificate verification
client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = client.SecureTravelDB

# Collections required for the evaluation
users_collection = db.users
itineraries_collection = db.itineraries
bookings_collection = db.bookings
logs_collection = db.logs
otp_collection = db.otps

# ============================================================================
# REQUIREMENT 2: ACCESS CONTROL MATRIX (3 marks)
# Complete implementation with 3 Subjects × 2 Objects
# ============================================================================

# Define the 2 Objects (Resources) in the system
OBJECTS = {
    "itineraries": "Trip planning and itinerary management",
    "bookings": "Flight/hotel booking confirmations"
}

# Define the 3 Subjects (Roles) with their permissions
ACCESS_CONTROL_MATRIX = {
    # SUBJECT 1: Admin - Full system access
    "admin": {
        "itineraries": ["create", "read", "update", "delete", "share"],
        "bookings": ["create", "read", "update", "delete", "verify"]
    },
    
    # SUBJECT 2: Traveler - Regular user with standard access
    "traveler": {
        "itineraries": ["create", "read", "update", "delete", "share"],
        "bookings": ["create", "read", "verify"]
    },
    
    # SUBJECT 3: Guest - Limited read-only access
    "guest": {
        "itineraries": ["read"],
        "bookings": ["read"]
    }
}

# Simplified access for quick checks (backward compatible)
ACCESS_MATRIX = {
    "admin": ["create", "read", "update", "delete", "share", "verify"],
    "traveler": ["create", "read", "update", "delete", "share"],
    "guest": ["read"]
}

# ============================================================================
# ACCESS CONTROL POLICY DEFINITIONS & JUSTIFICATIONS
# ============================================================================
ACCESS_POLICIES = {
    "admin": {
        "description": "System administrator with full privileges",
        "justification": "Needs complete access for system maintenance, user support, and security auditing",
        "restrictions": "Cannot view encrypted itinerary content without proper authorization"
    },
    
    "traveler": {
        "description": "Standard user who creates and manages travel plans",
        "justification": "Needs CRUD operations on own data, can share itineraries with others",
        "restrictions": "Cannot access other users' data unless explicitly shared. Cannot delete bookings after confirmation."
    },
    
    "guest": {
        "description": "Temporary or limited access user",
        "justification": "Can view shared travel information, useful for travel companions or family members",
        "restrictions": "Read-only access. Cannot create, modify, or delete any data. Cannot access unshared content."
    }
}

# ============================================================================
# ACCESS CONTROL ENFORCEMENT HELPER
# ============================================================================
def check_access(role, object_type, action):
    """
    Check if a role has permission to perform an action on an object
    Returns: (allowed: bool, reason: str)
    """
    if role not in ACCESS_CONTROL_MATRIX:
        return False, f"Invalid role: {role}"
    
    if object_type not in ACCESS_CONTROL_MATRIX[role]:
        return False, f"Role '{role}' has no access to '{object_type}'"
    
    allowed_actions = ACCESS_CONTROL_MATRIX[role][object_type]
    
    if action in allowed_actions:
        return True, "Access granted"
    else:
        return False, f"Role '{role}' cannot perform '{action}' on '{object_type}'"

def get_access_summary(role):
    """
    Get human-readable summary of access permissions for a role
    Useful for display in UI and documentation
    """
    if role not in ACCESS_CONTROL_MATRIX:
        return {"error": "Invalid role"}
    
    summary = {
        "role": role,
        "policy": ACCESS_POLICIES.get(role, {}),
        "permissions": {}
    }
    
    for obj, actions in ACCESS_CONTROL_MATRIX[role].items():
        summary["permissions"][obj] = {
            "description": OBJECTS.get(obj, ""),
            "allowed_actions": actions
        }
    
    return summary

# ============================================================================
# DATABASE INITIALIZATION & VERIFICATION
# ============================================================================
def initialize_database():
    """
    Initialize database with indexes and constraints
    Called once during setup
    """
    try:
        # Create indexes for better performance
        users_collection.create_index("email", unique=True)
        itineraries_collection.create_index("owner")
        bookings_collection.create_index("itinerary_id")
        bookings_collection.create_index("user_email")
        logs_collection.create_index([("timestamp", -1)])
        otp_collection.create_index("email")
        otp_collection.create_index("created_at", expireAfterSeconds=300)
        
        print("✅ Database indexes created successfully")
        return True
    except Exception as e:
        print(f"⚠️  Index creation warning: {e}")
        return False

# Verify MongoDB Atlas connection
try:
    client.admin.command('ping')
    print("✅ Successfully connected to MongoDB Atlas!")
    print(f"📊 Database: {db.name}")
except Exception as e:
    print(f"❌ Cloud MongoDB connection failed: {e}")
    print("⚠️  Please check your connection string and network access settings")

# ============================================================================
# SAMPLE DATA FOR TESTING (Optional)
# ============================================================================
def create_sample_users():
    """
    Create sample users for testing all three roles
    Run this once to populate test data
    """
    from security_utils import hash_password, generate_rsa_keypair
    
    sample_users = [
        {
            "name": "Admin User",
            "email": "admin@travel.com",
            "password": "Admin@123",
            "role": "admin"
        },
        {
            "name": "John Traveler",
            "email": "john@travel.com",
            "password": "Travel@123",
            "role": "traveler"
        },
        {
            "name": "Guest User",
            "email": "guest@travel.com",
            "password": "Guest@123",
            "role": "guest"
        }
    ]
    
    for user in sample_users:
        if users_collection.find_one({"email": user["email"]}):
            print(f"⏭️  User {user['email']} already exists")
            continue
        
        private_key, public_key = generate_rsa_keypair()
        hashed_pw, salt = hash_password(user["password"])
        
        user_doc = {
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "salt": salt,
            "password_hash": hashed_pw,
            "rsa_private_key": private_key,
            "rsa_public_key": public_key,
            "failed_attempts": 0,
            "is_locked": False,
            "mfa_enabled": True,
            "created_at": datetime.now()
        }
        
        users_collection.insert_one(user_doc)
        print(f"✅ Created sample user: {user['email']} (Role: {user['role']})")

# Uncomment to create sample users on first run
# create_sample_users()

