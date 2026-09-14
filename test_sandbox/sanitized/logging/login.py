import logging
logger = logging.getLogger(__name__)

def login(user, password):
    logger.info("Login attempt user_id=%s", user.id)
