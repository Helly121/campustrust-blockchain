
import sqlite3
import os

DB_PATH = 'database/campus.db'

def check_schema():
    if not os.path.exists(DB_PATH):
        print(f"Database {DB_PATH} not found!")
        return

    conn = sqlite3.connect(DB_PATH)
    try:
        c = conn.cursor()
        print("Schema for feedback_responses:")
        cursor = c.execute("PRAGMA table_info(feedback_responses)")
        columns = cursor.fetchall()
        for col in columns:
            print(col)
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    check_schema()
