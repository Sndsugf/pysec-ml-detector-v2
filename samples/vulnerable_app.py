import os
import sqlite3
import pickle
import subprocess

API_SECRET_TOKEN = "sk_live_9876543210abcdef1234567890"

def get_user_profile(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT id, username, email FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchone()

def check_server_status(hostname):
    command = "ping -c 2 " + hostname
    os.system(command)

def restore_user_session(raw_bytes):
    session_data = pickle.loads(raw_bytes)
    return session_data

def calculate_discount(price, rate):
    if price < 0:
        return 0.0
    return round(price * (1 - rate), 2)
