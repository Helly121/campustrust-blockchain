import unittest
import os
import sys
import tempfile
import sqlite3
import hashlib
from datetime import datetime

# Add parent directory to path to import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, get_db_connection, create_tables

class CampusTrustTestCase(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp()
        app.config['TESTING'] = True
        
        # Override get_db_connection to use the temp database
        self.original_get_db_connection = app.view_functions['dashboard'].__globals__['get_db_connection']
        
        def mock_get_db_connection():
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn
            
        # Patch the function in app.py namespace (a bit hacky but works for simple scripts)
        # Actually, simpler to just patch the sqlite3.connect call or rely on the fact 
        # that app.py imports are already done.
        # Let's just monkeypatch the function in the module
        import app as app_module
        app_module.get_db_connection = mock_get_db_connection
        
        self.app = app.test_client()
        
        # Initialize DB
        with app_module.get_db_connection() as conn:
            # We need to run the CREATE TABLE statements. 
            # Since create_tables() in app.py uses get_db_connection(), it should use our mock now.
            # But wait, create_tables() was already called at module level in app.py.
            # We need to call it again for our temp db.
            pass
        
        # Manually create tables for the test DB
        app_module.create_tables()
        
        self.create_test_data(app_module)

    def tearDown(self):
        try:
            os.close(self.db_fd)
            os.unlink(self.db_path)
        except OSError:
            pass

    def create_test_data(self, app_module):
        conn = app_module.get_db_connection()
        
        # Create Users
        # 1. Admin (might already exist from create_tables)
        conn.execute("INSERT OR IGNORE INTO users (student_id, name, password_hash, role) VALUES ('admin', 'Admin', 'hash', 'admin')")
        # Ensure we get the ID whether it was just inserted or already existed
        self.admin_id = conn.execute("SELECT id FROM users WHERE student_id = 'admin'").fetchone()[0]
        
        # 2. Lead
        conn.execute("INSERT OR IGNORE INTO users (student_id, name, password_hash, role) VALUES ('lead', 'Lead User', 'hash', 'student')")
        self.lead_id = conn.execute("SELECT id FROM users WHERE student_id = 'lead'").fetchone()[0]
        
        # 3. Member
        conn.execute("INSERT OR IGNORE INTO users (student_id, name, password_hash, role) VALUES ('member', 'Member User', 'hash', 'student')")
        self.member_id = conn.execute("SELECT id FROM users WHERE student_id = 'member'").fetchone()[0]
        
        # 4. Outsider
        conn.execute("INSERT OR IGNORE INTO users (student_id, name, password_hash, role) VALUES ('outsider', 'Outsider', 'hash', 'student')")
        self.outsider_id = conn.execute("SELECT id FROM users WHERE student_id = 'outsider'").fetchone()[0]
        
        # Create Group
        conn.execute("INSERT INTO groups (name, description, creation_type, created_by, status, category, created_date) VALUES ('Test Group', 'A group for testing search', 'student_created', ?, 'active', 'Project', ?)", (self.lead_id, datetime.now().isoformat()))
        self.group_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        
        # Create Group 2 (different name for search test)
        conn.execute("INSERT INTO groups (name, description, creation_type, created_by, status, category, created_date) VALUES ('Other Club', 'Something else', 'student_created', ?, 'active', 'Club', ?)", (self.lead_id, datetime.now().isoformat()))
        
        # Add members
        conn.execute("INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, 'lead')", (self.group_id, self.lead_id))
        conn.execute("INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, 'member')", (self.group_id, self.member_id))
        
        conn.commit()
        conn.close()

    def login(self, user_id):
        with self.app.session_transaction() as sess:
            sess['user_id'] = user_id

    def test_search(self):
        self.login(self.outsider_id)
        
        # 1. Search for "Test"
        response = self.app.get('/groups/discover?q=Test')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Test Group', response.data)
        self.assertNotIn(b'Other Club', response.data)
        
        # 2. Search for "Club"
        response = self.app.get('/groups/discover?q=Club')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Other Club', response.data)
        self.assertNotIn(b'Test Group', response.data)
        
        # 3. Search for non-existent
        response = self.app.get('/groups/discover?q=NonExistent')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'No groups found matching', response.data)

    def test_permissions_buttons(self):
        # 1. Lead should see buttons
        self.login(self.lead_id)
        response = self.app.get(f'/groups/{self.group_id}')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'New Task', response.data)
        self.assertIn(b'New Milestone', response.data)
        
        # 2. Admin should see buttons
        self.login(self.admin_id)
        response = self.app.get(f'/groups/{self.group_id}')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'New Task', response.data)
        self.assertIn(b'New Milestone', response.data)
        
        # 3. Member should NOT see buttons
        self.login(self.member_id)
        response = self.app.get(f'/groups/{self.group_id}')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'data-bs-target="#addTaskModal"', response.data)
        self.assertNotIn(b'data-bs-target="#addMilestoneModal"', response.data)
        
        # 4. Outsider checking (though they might not see the group details effectively or just not be a member)
        # Logic in app.py allows viewing group details even if not member
        self.login(self.outsider_id)
        response = self.app.get(f'/groups/{self.group_id}')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'data-bs-target="#addTaskModal"', response.data)
        self.assertNotIn(b'data-bs-target="#addMilestoneModal"', response.data)

    def test_task_assignment(self):
        self.login(self.lead_id)
        
        # Create a task assigned to the member
        response = self.app.post(f'/groups/{self.group_id}/task', data={
            'title': 'Test Task',
            'description': 'Description',
            'assigned_to': self.member_id,
            'due_date': datetime.now().isoformat()[:10]
        })
        self.assertEqual(response.status_code, 200)
        
        # Verify the task appears with the member's name
        response = self.app.get(f'/groups/{self.group_id}')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Member User', response.data)  # Member name should be visible
        self.assertIn(b'Test Task', response.data)

    def test_feedback_list(self):
        # Mock blockchain recording
        import app as app_module
        original_record = app_module.record_feedback_on_chain
        app_module.record_feedback_on_chain = lambda a, b, c, d: "TEST_TX_ID_123"
        
        try:
            # 1. Admin creates feedback form
            self.login(self.admin_id)
            response = self.app.post('/feedback/create', data={
                'title': 'Course Feedback',
                'description': 'Tell us about the course',
                'questions': ['How was it?'],
                'question_types': ['text'],
                'question_required': ['on']
            }, follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            
            # 2. Verify it appears in /feedback/list for student
            self.login(self.member_id)
            response = self.app.get('/feedback/list')
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Course Feedback', response.data)
            self.assertIn(b'Start Survey', response.data)
            
            # 3. Submit feedback (Not anonymous to trigger blockchain)
            response = self.app.post('/feedback/1', data={
                'question_1': 'Great!'
            }, follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            
            # 4. Verify it shows as completed
            response = self.app.get('/feedback/list')
            self.assertIn(b'Completed', response.data)
            
            # 5. Verify Blockchain Reference in Feedback Form directly
            response = self.app.get('/feedback/1')
            self.assertIn(b'TEST_TX_ID_123', response.data)
            
            # 6. Verify Permission Restrictions
            # Student should NOT see "Create Feedback Form" on dashboard
            response = self.app.get('/dashboard')
            self.assertNotIn(b'Create Feedback Form', response.data)
            
            # Student should NOT see "Create New Form" on list
            response = self.app.get('/feedback/list')
            self.assertNotIn(b'Create New Form', response.data)
            self.assertNotIn(b'View Results', response.data)
            
            # Student should NOT be able to access create route
            response = self.app.get('/feedback/create', follow_redirects=True)
            self.assertIn(b'Admin only', response.data)
            
            # Student should NOT be able to access results route
            response = self.app.get('/feedback/1/results', follow_redirects=True)
            self.assertIn(b'Unauthorized', response.data)

            # 7. Verify Admin CAN see results and TX ID
            self.login(self.admin_id)
            response = self.app.get('/feedback/1/results')
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'TEST_TX_ID_123', response.data)
            self.assertIn(b'lora.algokit.io', response.data)
            
        finally:
            app_module.record_feedback_on_chain = original_record

    def test_member_count(self):
        # 1. Initially there are 2 members (lead + member) from setUp
        self.login(self.member_id)
        
        # 2. Check discover page for member count
        response = self.app.get('/groups/discover')
        self.assertIn(b'2 Members', response.data)
        
        # 3. Join with another user (outsider)
        self.login(self.outsider_id)
        # join_group usually redirects to group_detail
        self.app.post(f'/groups/{self.group_id}/join', follow_redirects=True)
        
        # 4. Check discover again, should be 3 members
        response = self.app.get('/groups/discover')
        self.assertIn(b'3 Members', response.data)

    def test_admin_logs(self):
        # 1. Login as Admin
        self.login(self.admin_id)
        
        # 2. Perform an action that triggers a log (e.g., create group)
        self.app.post('/groups/admin/create', data={
            'name': 'Log Test Group',
            'description': 'Testing logs',
            'category': 'Project',
            'members': []
        }, follow_redirects=True)
        
        # 3. Check Admin Transactions Page
        response = self.app.get('/admin/transactions')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Created group Log Test Group', response.data)
        self.assertIn(b'GROUP_CREATE_ADMIN', response.data)
        
        # 4. Check File Log
        import app as app_module
        log_path = os.path.join(os.path.dirname(os.path.abspath(app_module.__file__)), 'transaction_logs.txt')
        
        # Ensure file exists
        self.assertTrue(os.path.exists(log_path))
        
        # Read file and check for entry
        with open(log_path, 'r') as f:
            content = f.read()
            self.assertIn('GROUP_CREATE_ADMIN', content)
            self.assertIn('Created group Log Test Group', content)
            
    def tearDown(self):
        super().tearDown()
        # Clean up log file created during test
        import app as app_module
        log_path = os.path.join(os.path.dirname(os.path.abspath(app_module.__file__)), 'transaction_logs.txt')
        # We might want to keep it if the user wants it persistent, 
        # but for clean tests maybe we shouldn't delete it?
        # The user requested a persistent file. So let's NOT delete it, 
        # or maybe delete only the test entry?
        # For now, let's leave it as is, or maybe just check it exists.
        pass

if __name__ == '__main__':
    unittest.main()
