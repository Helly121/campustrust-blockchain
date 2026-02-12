import sqlite3

conn = sqlite3.connect('database/campus.db')
conn.row_factory = sqlite3.Row
cur = conn.cursor()

session = cur.execute('SELECT id FROM attendance_sessions LIMIT 1').fetchone()
session_id = session['id']

print(f"Session {session_id} Records:")
for row in cur.execute('SELECT * FROM attendance_records WHERE session_id = ?', (session_id,)):
    print(dict(row))

conn.close()
