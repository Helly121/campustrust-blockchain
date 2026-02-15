import sqlite3
import os

def migrate():
    db_path = os.path.join(os.path.dirname(__file__), 'database/campus.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    print("Migrating users table...")
    try:
        c.execute("ALTER TABLE users ADD COLUMN wallet_address TEXT")
        c.execute("ALTER TABLE users ADD COLUMN wallet_mnemonic TEXT")
        print(" - Added wallet columns to users.")
    except sqlite3.OperationalError as e:
        print(f" - Users table might already have columns: {e}")

    print("Migrating certificates table...")
    try:
        c.execute("ALTER TABLE certificates ADD COLUMN asset_id INTEGER")
        print(" - Added asset_id column to certificates.")
    except sqlite3.OperationalError as e:
        print(f" - Certificates table might already have column: {e}")

    conn.commit()
    conn.close()
    print("Migration complete.")

if __name__ == "__main__":
    migrate()
