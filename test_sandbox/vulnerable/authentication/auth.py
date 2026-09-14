import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

API_TOKEN = "s3cr3tHardcod3dApiT0ken9f8a7b6c"
