import sqlite3
import json
import sys
import os

# Ensure we can import app
sys.path.append(os.getcwd())
import sqlite3
import json

# Setup DB connection to get a valid session and user
conn = sqlite3.connect('database/campus.db')
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# Get a session
session = cur.execute('SELECT id FROM attendance_sessions LIMIT 1').fetchone()
if not session:
    print("No sessions found.")
    exit()

session_id = session['id']

# Get a student user
student = cur.execute('SELECT id FROM users WHERE role = "student" LIMIT 1').fetchone()
if not student:
    # Try getting any user if no student
    student = cur.execute('SELECT id FROM users LIMIT 1').fetchone()

user_id = student['id']
conn.close()

print(f"Testing marking attendance for Session {session_id}, User {user_id} as 'absent'")

# We need to simulate a login? 
# The app uses `session['user_id']`. 
# We can't easily reproduce via requests unless we mock the session or use a script that imports app.
# Better to use app.test_client().

from app import app

with app.test_client() as client:
    # Login as admin first
    with client.session_transaction() as sess:
        # We need an admin user id. 
        # From previous steps, Ethan Gade (ID 20) is admin.
        sess['user_id'] = 20
        sess['user_role'] = 'admin'
        
    # Send PUT request
    response = client.put(f'/attendance/{session_id}/{user_id}', 
                          json={'status': 'absent'},
                          follow_redirects=True)
    
    print(f"Response Status: {response.status_code}")
    print(f"Response Body: {response.get_json()}")
        
    if response.status_code != 200:
        print("Error!")
        print(response.data)

