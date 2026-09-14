def store(redis, user):
    redis.set("session_token:" + user.id, user.auth_token)
