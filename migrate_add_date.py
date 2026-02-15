import sqlite3
import os

def migrate():
    db_path = os.path.join(os.path.dirname(__file__), 'database/campus.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    try:
        c.execute("ALTER TABLE group_proposals ADD COLUMN created_date TIMESTAMP")
        print("Added created_date column to group_proposals")
    except sqlite3.OperationalError as e:
        print(f"Column might already exist or other error: {e}")
        
    conn.commit()
    conn.close()

if __name__ == "__main__":
    migrate()
