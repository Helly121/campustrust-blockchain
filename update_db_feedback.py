
import sqlite3
import os

DB_PATH = 'database/campus.db'

def migrate_db():
    if not os.path.exists(DB_PATH):
        print(f"Database {DB_PATH} not found!")
        return

    conn = sqlite3.connect(DB_PATH)
    try:
        c = conn.cursor()
        print("Checking feedback_responses table...")
        
        # Check if column exists
        cursor = c.execute("PRAGMA table_info(feedback_responses)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if 'comments' not in columns:
            print("Adding 'comments' column to feedback_responses...")
            c.execute("ALTER TABLE feedback_responses ADD COLUMN comments TEXT")
            conn.commit()
            print("Migration successful: Added 'comments' column.")
        else:
            print("'comments' column already exists. No changes needed.")
            
    except Exception as e:
        print(f"Migration failed: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_db()
