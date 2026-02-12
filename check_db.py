import sqlite3

conn = sqlite3.connect('database/campus.db')
conn.row_factory = sqlite3.Row
cur = conn.cursor()

print("Users:")
for user in cur.execute("SELECT id, student_id, name, role FROM users"):
    print(dict(user))

conn.close()
