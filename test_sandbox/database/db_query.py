"""
Database Vulnerabilities - db_query.py
"""

from flask import Flask, request

app = Flask(__name__)

# ================================================================
# 1. SQL Injection - SELECT
# ================================================================

@app.route('/user')
def get_user():
    """VULNERABLE: SQL Injection via string concatenation"""
    user_id = request.args.get('id', '1')
    query = "SELECT * FROM users WHERE id = " + user_id
    return f"Query: {query}"


def select_users(user_id):
    """VULNERABLE: SELECT SQL Injection"""
    return f"SELECT * FROM users WHERE id = {user_id}"


def get_user_by_name(name):
    """VULNERABLE: SQL Injection via f-string"""
    return f"SELECT * FROM users WHERE name = '{name}'"


# ================================================================
# 2. SQL Injection - INSERT
# ================================================================

def insert_user(name, email):
    """VULNERABLE: INSERT SQL Injection"""
    return f"INSERT INTO users (name, email) VALUES ('{name}', '{email}')"


# ================================================================
# 3. SQL Injection - UPDATE
# ================================================================

def update_user_password(user_id, password):
    """VULNERABLE: UPDATE SQL Injection"""
    return f"UPDATE users SET password = '{password}' WHERE id = {user_id}"


# ================================================================
# 4. SQL Injection - DELETE
# ================================================================

def delete_user(user_id):
    """VULNERABLE: DELETE SQL Injection"""
    return f"DELETE FROM users WHERE id = {user_id}"


# ================================================================
# 5. SQL Injection - execute() with %
# ================================================================

def execute_query_bad(query, params):
    """VULNERABLE: execute() with % formatting"""
    return f"cursor.execute('%s')" % query


# ================================================================
# 6. NoSQL Injection
# ================================================================

def nosql_find(collection, query):
    """VULNERABLE: NoSQL injection via find()"""
    return f"db.{collection}.find({{ name: '{query}' }})"


def nosql_find_one(collection, user_id):
    """VULNERABLE: NoSQL injection via findOne()"""
    return f"db.{collection}.findOne({{ id: {user_id} }})"


# ================================================================
# 7. GraphQL Injection
# ================================================================

def graphql_query(user_id):
    """VULNERABLE: GraphQL injection"""
    return f"gql`query {{ user(id: ${user_id}) {{ name }} }}`"


# ================================================================
# 8. ORM Injection (Sequelize, SQLAlchemy)
# ================================================================

def sequelize_injection(user_id):
    """VULNERABLE: Sequelize injection via raw query"""
    return f"sequelize.query('SELECT * FROM users WHERE id = {user_id}')"