import sqlite3

conn = sqlite3.connect('database/campus.db')
cur = conn.cursor()

# Promote Ethan Gade to admin
cur.execute("UPDATE users SET role = 'admin' WHERE name = 'Ethan Gade'")
# Fix admin user role
cur.execute("UPDATE users SET role = 'admin' WHERE student_id = 'admin'")

conn.commit()
print("Updated roles to admin for 'Ethan Gade' and 'admin'.")
conn.close()
