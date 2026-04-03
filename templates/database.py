from pymongo import MongoClient

# MongoDB connection (local example)
client = MongoClient("mongodb://localhost:27017/")

# Database name
db = client["security_portal"]

# Collection
users_collection = db["users"]
