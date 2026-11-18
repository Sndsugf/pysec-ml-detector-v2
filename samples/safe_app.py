import os
import sqlite3
import json
import subprocess

API_SECRET_TOKEN = os.environ.get("API_SECRET_TOKEN")

def get_user_profile(user_id: int):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()

def check_server_status(hostname: str):
    result = subprocess.run(["ping", "-c", "2", hostname], shell=False, capture_output=True, text=True)
    return result.stdout

def restore_user_session(raw_json: str):
    session_data = json.loads(raw_json)
    return session_data
