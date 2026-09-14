import bcrypt
import os

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

API_TOKEN = os.environ["API_TOKEN"]
