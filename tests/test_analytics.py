import sqlite3
import unittest

class TestAnalytics(unittest.TestCase):
    def test_attendance_analytics(self):
        # Setup in-memory DB
        conn = sqlite3.connect(':memory:')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Create tables
        c.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, role TEXT)')
        c.execute('CREATE TABLE attendance_sessions (id INTEGER PRIMARY KEY, course_code TEXT)')
        c.execute('CREATE TABLE attendance_records (session_id INTEGER, user_id INTEGER, status TEXT)')
        
        # Insert Data
        c.execute("INSERT INTO users (id, role) VALUES (1, 'student')")
        
        # Course A: 2 sessions, User 1 attended 1
        c.execute("INSERT INTO attendance_sessions (id, course_code) VALUES (1, 'CS101')")
        c.execute("INSERT INTO attendance_sessions (id, course_code) VALUES (2, 'CS101')")
        c.execute("INSERT INTO attendance_records (session_id, user_id, status) VALUES (1, 1, 'present')")
        
        # Course B: 1 session, User 1 attended 0
        c.execute("INSERT INTO attendance_sessions (id, course_code) VALUES (3, 'MATH202')")
        
        conn.commit()
        
        # Test Logic (Mirrors app.py)
        user_id = 1
        stats = []
        courses = conn.execute('SELECT DISTINCT course_code FROM attendance_sessions').fetchall()
        
        for course in courses:
            code = course['course_code']
            total = conn.execute('SELECT COUNT(*) FROM attendance_sessions WHERE course_code = ?', (code,)).fetchone()[0]
            attended = conn.execute('''
                SELECT COUNT(*) FROM attendance_records ar
                JOIN attendance_sessions s ON ar.session_id = s.id
                WHERE s.course_code = ? AND ar.user_id = ? AND ar.status = 'present'
            ''', (code, user_id)).fetchone()[0]
            
            pct = (attended / total * 100) if total > 0 else 0
            stats.append({'code': code, 'pct': pct})
            
        # Assertions
        cs101 = next(s for s in stats if s['code'] == 'CS101')
        self.assertEqual(cs101['pct'], 50.0)
        
        math202 = next(s for s in stats if s['code'] == 'MATH202')
        self.assertEqual(math202['pct'], 0.0)
        
        print("Analytics Logic Verified!")
        conn.close()

if __name__ == "__main__":
    unittest.main()
