import sqlite3
import os

def migrate_db():
    print("Migrating database for group member status...")
    conn = sqlite3.connect('database/campus.db')
    cursor = conn.cursor()
    
    try:
        # Check if column exists
        cursor.execute("SELECT status FROM group_members LIMIT 1")
    except sqlite3.OperationalError:
        print("Adding status column...")
        cursor.execute("ALTER TABLE group_members ADD COLUMN status TEXT DEFAULT 'accepted'")
        conn.commit()
    else:
        print("Column status already exists.")
        
    conn.close()
    print("Migration complete.")

if __name__ == "__main__":
    migrate_db()
