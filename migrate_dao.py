import sqlite3
import os

def migrate_dao():
    db_path = os.path.join(os.path.dirname(__file__), 'database/campus.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    print("Migrating for DAO features...")
    
    # 1. Update groups table
    print(" - Updating groups table...")
    try:
        c.execute("ALTER TABLE groups ADD COLUMN dao_app_id INTEGER")
        c.execute("ALTER TABLE groups ADD COLUMN treasury_address TEXT")
        print("   -> Added dao_app_id and treasury_address columns.")
    except sqlite3.OperationalError:
        print("   -> Columns likely already exist.")

    # 2. Create group_proposals table
    print(" - Creating group_proposals table...")
    c.execute('''CREATE TABLE IF NOT EXISTS group_proposals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        amount_algo REAL NOT NULL,
        recipient_address TEXT NOT NULL,
        status TEXT DEFAULT 'active',
        yes_votes INTEGER DEFAULT 0,
        no_votes INTEGER DEFAULT 0,
        end_time TEXT,
        tx_id TEXT,
        FOREIGN KEY(group_id) REFERENCES groups(id)
    )''')
    
    # 3. Create votes tracking table to prevent double voting
    print(" - Creating proposal_votes table...")
    c.execute('''CREATE TABLE IF NOT EXISTS proposal_votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        proposal_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        choice TEXT NOT NULL,
        FOREIGN KEY(proposal_id) REFERENCES group_proposals(id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        UNIQUE(proposal_id, user_id)
    )''')
    
    conn.commit()
    conn.close()
    print("DAO Migration complete.")

if __name__ == "__main__":
    migrate_dao()
