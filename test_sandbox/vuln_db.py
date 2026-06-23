"""
Vulnerable Database Operations
"""

import pickle
import yaml
import subprocess
import os

# ================================================================
# 1. SQL Injection
# ================================================================

def get_user_vuln(user_id):
    """VULNERABLE: SQL Injection"""
    return f"SELECT * FROM users WHERE id = {user_id}"


# ================================================================
# 2. Insecure Deserialization
# ================================================================

def deserialize_pickle(data):
    """VULNERABLE: pickle.loads() - RCE"""
    return pickle.loads(data)


def deserialize_yaml(data):
    """VULNERABLE: yaml.load() - RCE"""
    return yaml.load(data)


# ================================================================
# 3. Command Injection
# ================================================================

def run_command(user_input):
    """VULNERABLE: subprocess with shell=True"""
    return subprocess.Popen(user_input, shell=True)


def system_command(user_input):
    """VULNERABLE: os.system()"""
    os.system(user_input)


def eval_command(user_input):
    """VULNERABLE: eval()"""
    return eval(user_input)


# ================================================================
# 4. Path Traversal
# ================================================================

def read_file(filename):
    """VULNERABLE: Path traversal"""
    with open(f'files/{filename}', 'r') as f:
        return f.read()


# ================================================================
# 5. NoSQL Injection
# ================================================================

def nosql_find(collection, query):
    """VULNERABLE: NoSQL injection"""
    return f"db.{collection}.find({{ name: '{query}' }})"