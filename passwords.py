from database import users_collection
from werkzeug.security import generate_password_hash, check_password_hash

# Create new user
def create_user(username, password, role):
    hashed_password = generate_password_hash(password)

    user = {
        "username": username,
        "password": hashed_password,
        "role": role,
        "status": "active"
    }

    users_collection.insert_one(user)

# Find user by username
def get_user(username):
    return users_collection.find_one({"username": username})

# Verify password
def verify_password(stored_password, input_password):
    return check_password_hash(stored_password, input_password)
