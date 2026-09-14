import hashlib

def store(redis, user):
    key = hashlib.sha256(user.auth_token.encode()).hexdigest()
    redis.set("session:" + user.id, key, ex=3600)
