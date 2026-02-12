
import sqlite3

def delete_group(group_id):
    conn = sqlite3.connect(r'd:\MLSC hackathon\campus-trust\campus-trust\database\campus.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM groups WHERE id = ?", (group_id,))
    conn.commit()
    conn.close()
    print(f"Group {group_id} deleted.")

if __name__ == "__main__":
    delete_group(6)
