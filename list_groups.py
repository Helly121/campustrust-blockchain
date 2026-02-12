
import sqlite3

def list_groups():
    conn = sqlite3.connect(r'd:\MLSC hackathon\campus-trust\campus-trust\database\campus.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM groups")
    groups = cursor.fetchall()
    conn.close()
    
    print("Groups:")
    for group in groups:
        print(f"ID: {group[0]}, Name: {group[1]}")

if __name__ == "__main__":
    list_groups()
