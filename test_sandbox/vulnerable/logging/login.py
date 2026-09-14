import logging
logger = logging.getLogger(__name__)

def login(username, password):
    logger.info("Login attempt user=%s password=%s", username, password)
