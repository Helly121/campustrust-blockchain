from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import sqlite3
import hashlib
import datetime
from werkzeug.utils import secure_filename
from utils.hash_utils import get_file_hash
from algorand.store_hash import store_on_chain
from utils.blockchain_utils import (
    record_attendance_on_chain,
    record_feedback_on_chain,
    record_group_task_on_chain,
    record_group_milestone_on_chain
)
from algorand.advanced_features import (
    send_algo_payment, create_asa, mint_nft, deploy_smart_contract, 
    call_bank_deposit, call_bank_withdraw, get_contract_history
)
try:
    from algorand.contracts.simple_bank import approval_program, clear_state_program
except:
    approval_program = None
    clear_state_program = None

app = Flask(__name__)
app.secret_key = 'super-secret-key-change-in-production'
UPLOAD_FOLDER = 'uploads/certificates'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_db_connection():
    db_path = os.path.join(app.root_path, 'database/campus.db')
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'student'
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        filename TEXT,
        cert_hash TEXT UNIQUE,
        tx_id TEXT,
        upload_date TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS elections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        description TEXT,
        created_by INTEGER,
        created_date TEXT,
        status TEXT DEFAULT 'active'
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS candidates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        election_id INTEGER,
        name TEXT,
        FOREIGN KEY(election_id) REFERENCES elections(id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        election_id INTEGER,
        user_id INTEGER,
        candidate_id INTEGER,
        tx_id TEXT,
        vote_date TEXT,
        UNIQUE(election_id, user_id)
    )''')

    # Attendance Tracking Tables
    c.execute('''CREATE TABLE IF NOT EXISTS attendance_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_by INTEGER NOT NULL,
        course_code TEXT,
        session_date DATE,
        session_time TIME,
        status TEXT DEFAULT 'active',
        created_at TEXT,
        FOREIGN KEY(created_by) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS attendance_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        marked_by INTEGER,
        status TEXT DEFAULT 'absent',
        check_in_time TEXT,
        marked_at TEXT,
        tx_id TEXT,
        FOREIGN KEY(session_id) REFERENCES attendance_sessions(id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(marked_by) REFERENCES users(id),
        UNIQUE(session_id, user_id)
    )''')

    # Feedback Collection Tables
    c.execute('''CREATE TABLE IF NOT EXISTS feedback_forms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_by INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        form_type TEXT DEFAULT 'feedback',
        is_active INTEGER DEFAULT 1,
        allow_anonymous INTEGER DEFAULT 1,
        created_date TEXT,
        closed_date TEXT,
        FOREIGN KEY(created_by) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS feedback_questions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        form_id INTEGER NOT NULL,
        question_text TEXT NOT NULL,
        question_type TEXT DEFAULT 'text',
        required INTEGER DEFAULT 0,
        question_order INTEGER,
        FOREIGN KEY(form_id) REFERENCES feedback_forms(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS feedback_responses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        form_id INTEGER NOT NULL,
        user_id INTEGER,
        question_id INTEGER NOT NULL,
        response_text TEXT,
        is_anonymous INTEGER DEFAULT 0,
        response_date TEXT,
        tx_id TEXT,
        FOREIGN KEY(form_id) REFERENCES feedback_forms(id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(question_id) REFERENCES feedback_questions(id)
    )''')

    # Group Coordination Tables
    c.execute('''CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        creation_type TEXT DEFAULT 'admin_created',
        created_by INTEGER NOT NULL,
        created_date TEXT,
        status TEXT DEFAULT 'active',
        category TEXT,
        FOREIGN KEY(created_by) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS group_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        role TEXT DEFAULT 'member',
        status TEXT DEFAULT 'accepted',
        joined_date TEXT,
        FOREIGN KEY(group_id) REFERENCES groups(id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        UNIQUE(group_id, user_id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS group_tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        assigned_to INTEGER,
        due_date TEXT,
        status TEXT DEFAULT 'pending',
        created_date TEXT,
        completed_date TEXT,
        tx_id TEXT,
        FOREIGN KEY(group_id) REFERENCES groups(id),
        FOREIGN KEY(assigned_to) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS group_milestones (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        target_date TEXT,
        completed_date TEXT,
        proof_url TEXT,
        tx_id TEXT,
        FOREIGN KEY(group_id) REFERENCES groups(id)
    )''')

    # Transaction Logs Table
    c.execute('''CREATE TABLE IF NOT EXISTS transaction_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        tx_id TEXT,
        timestamp TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    
    # Create default admin
    admin_hash = hashlib.sha256('admin'.encode()).hexdigest()
    c.execute("INSERT OR IGNORE INTO users (student_id, name, password_hash, role) VALUES ('admin', 'Administrator', ?, 'admin')", (admin_hash,))
    
    conn.commit()
    conn.close()

create_tables()

def log_transaction(user_id, action, details, tx_id=None):
    try:
        timestamp = datetime.datetime.now().isoformat()
        
        # 1. DB Logging
        conn = get_db_connection()
        conn.execute('''INSERT INTO transaction_logs 
                       (user_id, action, details, tx_id, timestamp)
                       VALUES (?, ?, ?, ?, ?)''',
                    (user_id, action, details, tx_id, timestamp))
        conn.commit()
        conn.close()
        
        # 2. File Logging
        log_entry = f"[{timestamp}] User: {user_id} | Action: {action} | Details: {details} | TX: {tx_id or 'N/A'}\n"
        # Use absolute path or relative to CWD
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'transaction_logs.txt')
        with open(log_path, 'a') as f:
            f.write(log_entry)
            
    except Exception as e:
        print(f"Logging failed: {e}")

def get_current_user():
    if 'user_id' not in session:
        return None
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    return user

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        student_id = request.form['student_id']
        name = request.form['name']
        password = request.form['password']
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (student_id, name, password_hash) VALUES (?, ?, ?)',
                         (student_id, name, password_hash))
            conn.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Student ID already exists.')
        conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        student_id = request.form['student_id']
        password = request.form['password']
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE student_id = ? AND password_hash = ?',
                            (student_id, password_hash)).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@app.route('/dashboard')
def dashboard():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    certs = conn.execute('SELECT * FROM certificates WHERE user_id = ? ORDER BY upload_date DESC',
                         (user['id'],)).fetchall()
    elections = conn.execute('SELECT * FROM elections ORDER BY created_date DESC').fetchall()
    
    # Fetch pending invites
    invites = conn.execute('''SELECT g.* 
                              FROM groups g 
                              JOIN group_members gm ON g.id = gm.group_id 
                              WHERE gm.user_id = ? AND gm.status = 'invited' ''',
                           (user['id'],)).fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', user=user, certs=certs, elections=elections, invites=invites)

@app.route('/upload_certificate', methods=['GET', 'POST'])
def upload_certificate():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'certificate' not in request.files:
            flash('No file selected')
            return redirect(request.url)
        
        file = request.files['certificate']
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        
        # Calculate hash first (before stream is consumed by save)
        cert_hash = get_file_hash(file)
        
        # Save file
        file.save(filepath)
        
        conn = get_db_connection()
        existing = conn.execute('SELECT * FROM certificates WHERE cert_hash = ?', (cert_hash,)).fetchone()
        if existing:
            flash('This certificate hash already exists (possible duplicate/reuse).')
            conn.close()
            return redirect(url_for('dashboard'))
        
        try:
            txid = store_on_chain(cert_hash)
        except Exception as e:
            flash('Algorand transaction failed. Check account funding.')
            conn.close()
            return redirect(url_for('dashboard'))
        
        upload_date = datetime.datetime.now().isoformat()
        conn.execute('INSERT INTO certificates (user_id, filename, cert_hash, tx_id, upload_date) VALUES (?, ?, ?, ?, ?)',
                     (user['id'], filename, cert_hash, txid, upload_date))
        conn.commit()
        conn.close()
        
        flash(f'Certificate uploaded successfully! TxID: {txid}')
        return redirect(url_for('dashboard'))
    
    return render_template('upload_cert.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    result = None
    if request.method == 'POST':
        if 'certificate' not in request.files:
            flash('No file selected')
            return redirect(request.url)
        
        file = request.files['certificate']
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        
        cert_hash = get_file_hash(file)
        
        conn = get_db_connection()
        cert = conn.execute('''SELECT c.*, u.name, u.student_id 
                               FROM certificates c 
                               JOIN users u ON c.user_id = u.id 
                               WHERE c.cert_hash = ?''', (cert_hash,)).fetchone()
        conn.close()
        
        if cert:
            result = {
                'valid': True,
                'student_name': cert['name'],
                'student_id': cert['student_id'],
                'filename': cert['filename'],
                'tx_id': cert['tx_id'],
                'hash': cert_hash
            }
        else:
            result = {'valid': False, 'hash': cert_hash}
    
    return render_template('verify_cert.html', result=result)

@app.route('/create_election', methods=['GET', 'POST'])
def create_election():
    user = get_current_user()
    if not user or user['role'] != 'admin':
        flash('Admin only')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        candidates_text = request.form['candidates']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO elections (title, description, created_by, created_date) VALUES (?, ?, ?, ?)',
                       (title, description, user['id'], datetime.datetime.now().isoformat()))
        election_id = cursor.lastrowid
        
        for name in candidates_text.strip().splitlines():
            if name.strip():
                cursor.execute('INSERT INTO candidates (election_id, name) VALUES (?, ?)',
                               (election_id, name.strip()))
        
        conn.commit()
        conn.close()
        flash('Election created!')
        return redirect(url_for('dashboard'))
    
    return render_template('create_election.html')

@app.route('/election/<int:eid>', methods=['GET', 'POST'])
def election_detail(eid):
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    election = conn.execute('SELECT * FROM elections WHERE id = ?', (eid,)).fetchone()
    if not election:
        flash('Election not found')
        return redirect(url_for('dashboard'))
    
    candidates = conn.execute('SELECT * FROM candidates WHERE election_id = ?', (eid,)).fetchall()
    has_voted = conn.execute('SELECT * FROM votes WHERE election_id = ? AND user_id = ?',
                             (eid, user['id'])).fetchone()
    
    if request.method == 'POST' and election['status'] == 'active' and not has_voted:
        candidate_id = request.form['candidate']
        vote_date = datetime.datetime.now().isoformat()
        
        note = f"VOTE|election:{eid}|candidate:{candidate_id}"
        try:
            txid = store_on_chain(note)
        except Exception:
            flash('Vote recording on blockchain failed')
            conn.close()
            return redirect(request.url)
        
        conn.execute('INSERT INTO votes (election_id, user_id, candidate_id, tx_id, vote_date) VALUES (?, ?, ?, ?, ?)',
                     (eid, user['id'], candidate_id, txid, vote_date))
        conn.commit()
        flash('Vote recorded!')
        return redirect(request.url)
    
    # Results
    results = conn.execute('''SELECT c.name, COUNT(v.id) as votes 
                              FROM candidates c 
                              LEFT JOIN votes v ON c.id = v.candidate_id 
                              WHERE c.election_id = ? 
                              GROUP BY c.id''', (eid,)).fetchall()
    
    # Fetch vote ledger for blockchain verification
    vote_records = conn.execute('''
        SELECT v.tx_id, v.vote_date, c.name as candidate_name
        FROM votes v
        JOIN candidates c ON v.candidate_id = c.id
        WHERE v.election_id = ?
        ORDER BY v.vote_date DESC
    ''', (eid,)).fetchall()
    
    conn.close()
    return render_template('election.html', election=election, candidates=candidates,
                           has_voted=has_voted, results=results, user=user, vote_records=vote_records)

@app.route('/end_election/<int:eid>')
def end_election(eid):
    user = get_current_user()
    if not user or user['role'] != 'admin':
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    conn.execute('UPDATE elections SET status = "ended" WHERE id = ?', (eid,))
    conn.commit()
    conn.close()
    flash('Election ended')
    return redirect(url_for('election_detail', eid=eid))

@app.route('/delete_election/<int:eid>')
def delete_election(eid):
    user = get_current_user()
    if not user or user['role'] != 'admin':
        flash('Admin only')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    election = conn.execute('SELECT * FROM elections WHERE id = ?', (eid,)).fetchone()
    
    if not election:
        flash('Election not found')
        conn.close()
        return redirect(url_for('dashboard'))
        
    if election['status'] != 'ended':
        flash('Cannot delete active election. End it first.')
        conn.close()
        return redirect(url_for('election_detail', eid=eid))

    # Delete related data
    conn.execute('DELETE FROM votes WHERE election_id = ?', (eid,))
    conn.execute('DELETE FROM candidates WHERE election_id = ?', (eid,))
    conn.execute('DELETE FROM elections WHERE id = ?', (eid,))
    
    conn.commit()
    conn.close()
    flash('Election deleted successfully')
    return redirect(url_for('dashboard'))

# ========================= ATTENDANCE TRACKING ROUTES =========================

@app.route('/attendance/create', methods=['GET', 'POST'])
def create_attendance_session():
    user = get_current_user()
    if not user or user['role'] not in ['admin', 'instructor']:
        flash('Admin or Instructor only')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        course_code = request.form['course_code']
        session_date = request.form['session_date']
        session_time = request.form['session_time']
        duration = int(request.form.get('duration', 60)) # Default 60 mins

        # Calculate end time
        start_datetime = datetime.datetime.strptime(f"{session_date} {session_time}", "%Y-%m-%d %H:%M")
        end_datetime = start_datetime + datetime.timedelta(minutes=duration)
        end_time_iso = end_datetime.isoformat()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO attendance_sessions
                         (created_by, course_code, session_date, session_time, end_time, created_at)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                      (user['id'], course_code, session_date, session_time, end_time_iso, datetime.datetime.now().isoformat()))
        conn.commit()
        session_id = cursor.lastrowid
        conn.close()

        flash(f'Attendance session created for {course_code} with {duration} min duration')
        return redirect(url_for('attendance_session', session_id=session_id))

    return render_template('attendance_create.html')

@app.route('/attendance/<int:session_id>', methods=['GET', 'POST'])
def attendance_session(session_id):
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    conn = get_db_connection()
    session_info = conn.execute('SELECT * FROM attendance_sessions WHERE id = ?', (session_id,)).fetchone()

    if not session_info:
        flash('Session not found')
        return redirect(url_for('dashboard'))

    # Check if user has already marked attendance
    existing_record = conn.execute('SELECT * FROM attendance_records WHERE session_id = ? AND user_id = ?',
                                 (session_id, user['id'])).fetchone()
    
    # Check deadline
    now = datetime.datetime.now().isoformat()
    is_expired = False
    if session_info['end_time'] and now > session_info['end_time']:
        is_expired = True

    if request.method == 'POST' and not existing_record:
        if is_expired:
            flash('Check-in time has expired for this session.')
            return redirect(request.url)
            
        # Student self check-in
        check_in_time = datetime.datetime.now().isoformat()
        try:
            txid = record_attendance_on_chain(session_id, user['id'], 'present', user['id'])
        except Exception as e:
            flash('Failed to record attendance on blockchain')
            conn.close()
            return redirect(request.url)

        conn.execute('''INSERT INTO attendance_records
                       (session_id, user_id, marked_by, status, check_in_time, marked_at, tx_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?)''',
                   (session_id, user['id'], user['id'], 'present', check_in_time, check_in_time, txid))
        conn.commit()
        
        # Log transaction
        log_transaction(user['id'], 'ATTENDANCE_CHECKIN', f"Self check-in for session {session_id}", txid)
        
        flash('Check-in recorded!')
        return redirect(request.url)

    # Get all students and their attendance status
    all_students = conn.execute('SELECT * FROM users WHERE role = "student" ORDER BY name').fetchall()
    attendance_records = conn.execute('SELECT * FROM attendance_records WHERE session_id = ?',
                                    (session_id,)).fetchall()

    attendance_dict = {rec['user_id']: rec for rec in attendance_records}

    # Check if current user is the instructor who created this session
    is_instructor = session_info['created_by'] == user['id'] or user['role'] == 'admin'

    conn.close()

    return render_template('attendance_session.html',
                         session_info=session_info,
                         students=all_students,
                         attendance_dict=attendance_dict,
                         existing_record=existing_record,
                         is_instructor=is_instructor,
                         user=user,
                         now=now)

@app.route('/attendance/<int:session_id>/<int:user_id>', methods=['PUT'])
def mark_attendance(session_id, user_id):
    user = get_current_user()
    if not user or user['role'] not in ['admin', 'instructor']:
        return jsonify({'error': 'Unauthorized'}), 403

    status = request.json.get('status', 'absent')
    marked_time = datetime.datetime.now().isoformat()

    conn = get_db_connection()

    # Check if record exists
    existing = conn.execute('SELECT * FROM attendance_records WHERE session_id = ? AND user_id = ?',
                           (session_id, user_id)).fetchone()

    try:
        txid = record_attendance_on_chain(session_id, user_id, status, user['id'])
    except Exception as e:
        return jsonify({'error': 'Blockchain recording failed'}), 500

    if existing:
        conn.execute('UPDATE attendance_records SET status = ?, marked_by = ?, marked_at = ?, tx_id = ? WHERE session_id = ? AND user_id = ?',
                    (status, user['id'], marked_time, txid, session_id, user_id))
    else:
        conn.execute('''INSERT INTO attendance_records
                       (session_id, user_id, marked_by, status, marked_at, tx_id)
                       VALUES (?, ?, ?, ?, ?, ?)''',
                   (session_id, user_id, user['id'], status, marked_time, txid))

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'tx_id': txid})

@app.route('/attendance/list')
def attendance_list():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    conn = get_db_connection()

    if user['role'] in ['admin', 'instructor']:
        # Show all sessions created by this user or all sessions for admin
        if user['role'] == 'admin':
            sessions = conn.execute('SELECT * FROM attendance_sessions ORDER BY session_date DESC, session_time DESC').fetchall()
        else:
            sessions = conn.execute('SELECT * FROM attendance_sessions WHERE created_by = ? ORDER BY session_date DESC, session_time DESC',
                                  (user['id'],)).fetchall()
    else:
        # Students see only active sessions
        sessions = conn.execute('SELECT * FROM attendance_sessions WHERE status = "active" ORDER BY session_date DESC').fetchall()

    conn.close()
    return render_template('attendance_list.html', sessions=sessions, user=user)

@app.route('/attendance/report/<course_code>')
def attendance_report(course_code):
    user = get_current_user()
    if not user or user['role'] not in ['admin', 'instructor']:
        flash('Instructor only')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()

    # Get all sessions for this course
    sessions = conn.execute('''SELECT * FROM attendance_sessions
                              WHERE course_code = ? ORDER BY session_date DESC, session_time DESC''',
                           (course_code,)).fetchall()

    # Get attendance summary
    summary = conn.execute('''SELECT u.id, u.name, u.student_id,
                             SUM(CASE WHEN ar.status = "present" THEN 1 ELSE 0 END) as present_count,
                             COUNT(ar.id) as total_sessions
                             FROM users u
                             LEFT JOIN attendance_records ar ON u.id = ar.user_id
                             LEFT JOIN attendance_sessions s ON ar.session_id = s.id
                             WHERE u.role = "student" AND s.course_code = ?
                             GROUP BY u.id
                             ORDER BY u.name''',
                            (course_code,)).fetchall()

    conn.close()

    return render_template('attendance_report.html',
                         course_code=course_code,
                         sessions=sessions,
                         summary=summary,
                         user=user)

# ========================= FEEDBACK COLLECTION ROUTES =========================

@app.route('/feedback/create', methods=['GET', 'POST'])
def create_feedback():
    user = get_current_user()
    if not user or user['role'] != 'admin':
        flash('Admin only')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        allow_anonymous = 1 if request.form.get('allow_anonymous') else 0

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO feedback_forms
                         (created_by, title, description, allow_anonymous, created_date, is_active)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                      (user['id'], title, description, allow_anonymous, datetime.datetime.now().isoformat(), 1))
        form_id = cursor.lastrowid

        # Add questions
        question_texts = request.form.getlist('questions')
        question_types = request.form.getlist('question_types')
        question_reqd = request.form.getlist('question_required')

        for i, q_text in enumerate(question_texts):
            if q_text.strip():
                required = 1 if (i < len(question_reqd) and question_reqd[i]) else 0
                q_type = question_types[i] if i < len(question_types) else 'text'
                cursor.execute('''INSERT INTO feedback_questions
                                 (form_id, question_text, question_type, required, question_order)
                                 VALUES (?, ?, ?, ?, ?)''',
                              (form_id, q_text.strip(), q_type, required, i))

        conn.commit()
        conn.close()

        flash('Feedback form created!')
        return redirect(url_for('feedback_form', form_id=form_id))

    return render_template('feedback_create.html')

@app.route('/feedback/<int:form_id>', methods=['GET', 'POST'])
def feedback_form(form_id):
    user = get_current_user()

    conn = get_db_connection()
    form_info = conn.execute('SELECT * FROM feedback_forms WHERE id = ?', (form_id,)).fetchone()

    if not form_info or not form_info['is_active']:
        flash('Form not found or is closed')
        return redirect(url_for('dashboard'))

    questions = conn.execute('SELECT * FROM feedback_questions WHERE form_id = ? ORDER BY question_order',
                            (form_id,)).fetchall()

    if request.method == 'POST' and user:
        is_anonymous = request.form.get('is_anonymous') == 'on'
        response_date = datetime.datetime.now().isoformat()

        for q in questions:
            response_text = request.form.get(f'question_{q["id"]}')

            if response_text is not None:
                response_hash = hashlib.sha256(response_text.encode()).hexdigest() if response_text else ''

                try:
                    if is_anonymous:
                        # Anonymous: not stored on blockchain for privacy
                        txid = None
                    else:
                        # Verified: store on blockchain
                        txid = record_feedback_on_chain(form_id, user['id'], q['id'], response_hash)
                except Exception as e:
                    flash('Failed to record feedback on blockchain')
                    conn.close()
                    return redirect(request.url)

                conn.execute('''INSERT INTO feedback_responses
                               (form_id, user_id, question_id, response_text, is_anonymous, response_date, tx_id)
                               VALUES (?, ?, ?, ?, ?, ?, ?)''',
                           (form_id, user['id'] if not is_anonymous else None,
                            q['id'], response_text, 1 if is_anonymous else 0, response_date, txid))

        conn.commit()
        
        # Log transaction (only if verified)
        if not is_anonymous:
             # Just logging the last txid if multiple questions, or generic log
             # Ideally we log per response but that's too much. Let's log the form submission.
             # We use the txid from the last question if available, or just note it's on chain
             last_tx = txid if 'txid' in locals() else None
             log_transaction(user['id'], 'FEEDBACK_SUBMIT', f"Submitted feedback for form {form_id}", last_tx)
             
        flash('Feedback submitted!')
        return redirect(url_for('dashboard'))

    # Check if user has already responded
    response = None
    if user:
        response = conn.execute('SELECT * FROM feedback_responses WHERE form_id = ? AND user_id = ?',
                               (form_id, user['id'])).fetchone()
    
    conn.close()

    return render_template('feedback_form.html',
                         form=form_info,
                         questions=questions,
                         response=response,
                         user=user,
                         form_id=form_id)

@app.route('/feedback/<int:form_id>/results')
def feedback_results(form_id):
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    conn = get_db_connection()
    form_info = conn.execute('SELECT * FROM feedback_forms WHERE id = ?', (form_id,)).fetchone()

    if not form_info:
        flash('Form not found')
        return redirect(url_for('dashboard'))

    # Check authorization
    if user['role'] != 'admin':
        flash('Unauthorized')
        return redirect(url_for('dashboard'))

    questions = conn.execute('SELECT * FROM feedback_questions WHERE form_id = ? ORDER BY question_order',
                            (form_id,)).fetchall()

    results = {}
    for q in questions:
        # Get individual responses with tx_id
        responses = conn.execute('''SELECT response_text, is_anonymous, tx_id
                                   FROM feedback_responses
                                   WHERE question_id = ?
                                   ORDER BY id DESC''',
                               (q['id'],)).fetchall()
        
        # Group by text to show counts, but keep individual details if needed
        # For this view, listing individual responses with TX ID is better than grouping
        # if we want to show verification.
        # However, the previous view was grouped.
        # Let's change the view to list responses with their verification status.
        
        results[q['id']] = {
            'question': q['question_text'],
            'type': q['question_type'],
            'responses': responses
        }

    response_count = conn.execute('SELECT COUNT(DISTINCT user_id) FROM feedback_responses WHERE form_id = ? AND user_id IS NOT NULL',
                                 (form_id,)).fetchone()[0]
    anon_response_count = conn.execute('SELECT COUNT(DISTINCT id) FROM feedback_responses WHERE form_id = ? AND is_anonymous = 1',
                                      (form_id,)).fetchone()[0]

    conn.close()

    return render_template('feedback_results.html',
                         form=form_info,
                         questions=questions,
                         results=results,
                         response_count=response_count,
                         anon_response_count=anon_response_count,
                         user=user)

@app.route('/feedback/list')
def feedback_list():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    conn = get_db_connection()
    
    # Get active forms
    forms = conn.execute('SELECT * FROM feedback_forms WHERE is_active = 1 ORDER BY created_date DESC').fetchall()
    
    # Get user's responses
    responded_forms = set()
    rows = conn.execute('SELECT DISTINCT form_id FROM feedback_responses WHERE user_id = ?', (user['id'],)).fetchall()
    for row in rows:
        responded_forms.add(row['form_id'])
    
    conn.close()
    
    return render_template('feedback_list.html', forms=forms, responded_forms=responded_forms, user=user)

@app.route('/feedback/<int:form_id>/close', methods=['PUT'])
def close_feedback(form_id):
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db_connection()
    form_info = conn.execute('SELECT * FROM feedback_forms WHERE id = ?', (form_id,)).fetchone()

    if not form_info or (user['id'] != form_info['created_by'] and user['role'] != 'admin'):
        conn.close()
        return jsonify({'error': 'Unauthorized'}), 403

    conn.execute('UPDATE feedback_forms SET is_active = 0, closed_date = ? WHERE id = ?',
                (datetime.datetime.now().isoformat(), form_id))
    conn.commit()
    conn.close()

    return jsonify({'success': True})

# ========================= GROUP COORDINATION ROUTES =========================

@app.route('/groups/admin/create', methods=['GET', 'POST'])
def admin_create_group():
    user = get_current_user()
    if not user or user['role'] != 'admin':
        flash('Admin only')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        category = request.form['category']
        selected_members = request.form.getlist('members')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO groups
                         (name, description, creation_type, created_by, created_date, category)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                      (name, description, 'admin_created', user['id'], datetime.datetime.now().isoformat(), category))
        group_id = cursor.lastrowid

        # Add members
        for member_id in selected_members:
            try:
                cursor.execute('''INSERT INTO group_members
                                 (group_id, user_id, role, joined_date)
                                 VALUES (?, ?, ?, ?)''',
                              (group_id, int(member_id), 'member', datetime.datetime.now().isoformat()))
            except:
                pass

        # Add group creator as lead
        cursor.execute('''INSERT INTO group_members
                         (group_id, user_id, role, joined_date)
                         VALUES (?, ?, ?, ?)''',
                      (group_id, user['id'], 'lead', datetime.datetime.now().isoformat()))

        conn.commit()
        conn.close()
        
        # Log transaction
        log_transaction(user['id'], 'GROUP_CREATE_ADMIN', f"Created group {name} ({category})")

        flash('Group created!')
        return redirect(url_for('group_detail', group_id=group_id))

    conn = get_db_connection()
    students = conn.execute('SELECT * FROM users WHERE role = "student" ORDER BY name').fetchall()
    conn.close()

    return render_template('group_admin_create.html', students=students)

@app.route('/groups/create', methods=['GET', 'POST'])
def create_group():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        category = request.form.get('category', 'Project')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO groups
                         (name, description, creation_type, created_by, created_date, category, status)
                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                      (name, description, 'student_created', user['id'], datetime.datetime.now().isoformat(), category, 'active'))
        group_id = cursor.lastrowid

        # Add creator as lead
        cursor.execute('''INSERT INTO group_members
                         (group_id, user_id, role, joined_date)
                         VALUES (?, ?, ?, ?)''',
                      (group_id, user['id'], 'lead', datetime.datetime.now().isoformat()))

        conn.commit()
        conn.close()
        
        # Log transaction
        log_transaction(user['id'], 'GROUP_CREATE_STUDENT', f"Created group {name} ({category})")

        flash('Group created!')
        return redirect(url_for('group_detail', group_id=group_id))

    return render_template('group_create.html')

@app.route('/groups/discover')
def discover_groups():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    conn = get_db_connection()
    
    query = request.args.get('q', '').strip()

    if query:
        # Search for groups
        groups = conn.execute('''SELECT g.*, COUNT(gm.user_id) as member_count
                                FROM groups g
                                LEFT JOIN group_members gm ON g.id = gm.group_id
                                WHERE g.creation_type = "student_created" 
                                AND g.status = "active"
                                AND (g.name LIKE ? OR g.description LIKE ?)
                                GROUP BY g.id
                                ORDER BY g.created_date DESC''', 
                                (f'%{query}%', f'%{query}%')).fetchall()
    else:
        # Get all student-created groups
        groups = conn.execute('''SELECT g.*, COUNT(gm.user_id) as member_count
                                FROM groups g
                                LEFT JOIN group_members gm ON g.id = gm.group_id
                                WHERE g.creation_type = "student_created" AND g.status = "active"
                                GROUP BY g.id
                                ORDER BY g.created_date DESC''').fetchall()

    # Get user's groups
    user_groups = conn.execute('''SELECT DISTINCT g.id FROM groups g
                                 JOIN group_members gm ON g.id = gm.group_id
                                 WHERE gm.user_id = ?''', (user['id'],)).fetchall()
    user_group_ids = {g['id'] for g in user_groups}

    conn.close()

    return render_template('group_discover.html', groups=groups, user_group_ids=user_group_ids, user=user, query=query)

@app.route('/groups/<int:group_id>/join', methods=['POST'])
def join_group(group_id):
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    conn = get_db_connection()

    # Check if already member
    existing = conn.execute('SELECT * FROM group_members WHERE group_id = ? AND user_id = ?',
                           (group_id, user['id'])).fetchone()

    if not existing:
        conn.execute('''INSERT INTO group_members
                       (group_id, user_id, role, joined_date)
                       VALUES (?, ?, ?, ?)''',
                   (group_id, user['id'], 'member', datetime.datetime.now().isoformat()))
        conn.commit()
        flash('Joined group!')

    conn.close()
    return redirect(url_for('group_detail', group_id=group_id))

@app.route('/groups/<int:group_id>/leave', methods=['POST'])
def leave_group(group_id):
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute('DELETE FROM group_members WHERE group_id = ? AND user_id = ?', (group_id, user['id']))
    conn.commit()
    conn.close()

    flash('Left group')
    return redirect(url_for('dashboard'))

@app.route('/groups/<int:group_id>')
def group_detail(group_id):
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    conn = get_db_connection()
    group = conn.execute('SELECT * FROM groups WHERE id = ?', (group_id,)).fetchone()

    if not group:
        flash('Group not found')
        return redirect(url_for('dashboard'))



    # Get members
    members = conn.execute('''SELECT u.id, u.name, u.student_id, gm.role, gm.status
                             FROM group_members gm
                             JOIN users u ON gm.user_id = u.id
                             WHERE gm.group_id = ? ORDER BY gm.role DESC, u.name''',
                          (group_id,)).fetchall()

    # Get tasks
    tasks = conn.execute('''SELECT t.*, u.name as assignee_name 
                           FROM group_tasks t 
                           LEFT JOIN users u ON t.assigned_to = u.id 
                           WHERE t.group_id = ? 
                           ORDER BY t.due_date''',
                        (group_id,)).fetchall()

    # Get milestones
    milestones = conn.execute('SELECT * FROM group_milestones WHERE group_id = ? ORDER BY target_date',
                             (group_id,)).fetchall()

    # Check if user is member
    is_member = conn.execute('SELECT * FROM group_members WHERE group_id = ? AND user_id = ?',
                            (group_id, user['id'])).fetchone() is not None

    # Check if user is lead
    is_lead = conn.execute('SELECT * FROM group_members WHERE group_id = ? AND user_id = ? AND role = "lead"',
                          (group_id, user['id'])).fetchone() is not None

    conn.close()

    return render_template('group_detail.html',
                         group=group,
                         members=members,
                         tasks=tasks,
                         milestones=milestones,
                         is_member=is_member,
                         is_lead=is_lead,
                         user=user)

@app.route('/groups/<int:group_id>/delete', methods=['POST'])
def delete_group(group_id):
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    conn = get_db_connection()
    
    # Check if user is lead or admin
    is_lead = conn.execute('SELECT * FROM group_members WHERE group_id = ? AND user_id = ? AND role = "lead"',
                          (group_id, user['id'])).fetchone() is not None
    
    if not is_lead and user['role'] != 'admin':
        conn.close()
        flash('Only group leads can delete groups')
        return redirect(url_for('group_detail', group_id=group_id))

    # Delete everything related to group
    conn.execute('DELETE FROM group_tasks WHERE group_id = ?', (group_id,))
    conn.execute('DELETE FROM group_milestones WHERE group_id = ?', (group_id,))
    conn.execute('DELETE FROM group_members WHERE group_id = ?', (group_id,))
    conn.execute('DELETE FROM groups WHERE id = ?', (group_id,))
    
    conn.commit()
    conn.close()
    
    flash('Group deleted successfully')
    return redirect(url_for('dashboard'))

@app.route('/groups/<int:group_id>/invite', methods=['POST'])
def invite_member(group_id):
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    conn = get_db_connection()
    
    # Check if user is lead or admin
    is_lead = conn.execute('SELECT * FROM group_members WHERE group_id = ? AND user_id = ? AND role = "lead"',
                          (group_id, user['id'])).fetchone() is not None
    
    if not is_lead and user['role'] != 'admin':
        conn.close()
        flash('Only group leads can invite members')
        return redirect(url_for('group_detail', group_id=group_id))

    student_id = request.form.get('student_id')
    
    # Find user
    target_user = conn.execute('SELECT * FROM users WHERE student_id = ?', (student_id,)).fetchone()
    
    if not target_user:
        conn.close()
        flash('Student ID not found')
        return redirect(url_for('group_detail', group_id=group_id))

    # Check if already member (accepted or invited)
    existing = conn.execute('SELECT * FROM group_members WHERE group_id = ? AND user_id = ?',
                           (group_id, target_user['id'])).fetchone()
    
    if existing:
        conn.close()
        if existing['status'] == 'invited':
            flash('User has already been invited')
        else:
            flash('User is already a member')
        return redirect(url_for('group_detail', group_id=group_id))

    # Add member with 'invited' status
    conn.execute('''INSERT INTO group_members
                   (group_id, user_id, role, joined_date, status)
                   VALUES (?, ?, ?, ?, ?)''',
               (group_id, target_user['id'], 'member', datetime.datetime.now().isoformat(), 'invited'))
    conn.commit()
    conn.close()
    
    flash(f'Invitation sent to {target_user["name"]}')
    return redirect(url_for('group_detail', group_id=group_id))

@app.route('/groups/<int:group_id>/accept_invite', methods=['POST'])
def accept_invite(group_id):
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute('UPDATE group_members SET status = "accepted" WHERE group_id = ? AND user_id = ?',
                (group_id, user['id']))
    conn.commit()
    conn.close()
    
    flash('Incorporated into group!')
    return redirect(url_for('group_detail', group_id=group_id))

@app.route('/groups/<int:group_id>/decline_invite', methods=['POST'])
def decline_invite(group_id):
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute('DELETE FROM group_members WHERE group_id = ? AND user_id = ?',
                (group_id, user['id']))
    conn.commit()
    conn.close()
    
    flash('Invitation declined')
    return redirect(url_for('dashboard'))

@app.route('/groups/<int:group_id>/task', methods=['POST'])
def create_task(group_id):
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db_connection()

    conn = get_db_connection()

    # Check if user is group lead or admin (Restrict creation)
    is_lead = conn.execute('SELECT * FROM group_members WHERE group_id = ? AND user_id = ? AND role = "lead"',
                          (group_id, user['id'])).fetchone() is not None

    if not is_lead and user['role'] != 'admin':
        conn.close()
        return jsonify({'error': 'Not authorized'}), 403

    title = request.form.get('title')
    description = request.form.get('description')
    assigned_to = request.form.get('assigned_to')
    due_date = request.form.get('due_date')

    cursor = conn.cursor()
    cursor.execute('''INSERT INTO group_tasks
                     (group_id, title, description, assigned_to, due_date, created_date)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (group_id, title, description, assigned_to or None, due_date, datetime.datetime.now().isoformat()))
    task_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'task_id': task_id})

@app.route('/groups/<int:group_id>/task/<int:task_id>/complete', methods=['POST'])
def complete_task(group_id, task_id):
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    conn = get_db_connection()
    task = conn.execute('SELECT * FROM group_tasks WHERE id = ? AND group_id = ?', (task_id, group_id)).fetchone()

    if not task:
        conn.close()
        flash('Task not found')
        return redirect(url_for('group_detail', group_id=group_id))

    # Check if authorized (assignee, lead, or admin)
    is_lead = conn.execute('SELECT * FROM group_members WHERE group_id = ? AND user_id = ? AND role = "lead"',
                          (group_id, user['id'])).fetchone() is not None

    if task['assigned_to'] != user['id'] and not is_lead and user['role'] != 'admin':
        conn.close()
        flash('Not authorized to complete this task')
        return redirect(url_for('group_detail', group_id=group_id))

    completed_date = datetime.datetime.now().isoformat()
    try:
        txid = record_group_task_on_chain(group_id, task_id, user['id'])
    except Exception as e:
        conn.close()
        flash('Blockchain recording failed')
        return redirect(url_for('group_detail', group_id=group_id))

    conn.execute('''UPDATE group_tasks
                   SET status = "completed", completed_date = ?, tx_id = ?
                   WHERE id = ?''',
               (completed_date, txid, task_id))

    conn.commit()
    conn.close()
    
    flash('Task marked as completed!')
    return redirect(url_for('group_detail', group_id=group_id))

@app.route('/groups/<int:group_id>/task/<int:task_id>', methods=['PUT'])
def update_task(group_id, task_id):
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    new_status = request.json.get('status')

    conn = get_db_connection()
    task = conn.execute('SELECT * FROM group_tasks WHERE id = ? AND group_id = ?', (task_id, group_id)).fetchone()

    if not task:
        conn.close()
        return jsonify({'error': 'Task not found'}), 404

    # Check if authorized (assignee, lead, or admin)
    is_lead = conn.execute('SELECT * FROM group_members WHERE group_id = ? AND user_id = ? AND role = "lead"',
                          (group_id, user['id'])).fetchone() is not None

    if task['assigned_to'] != user['id'] and not is_lead and user['role'] != 'admin':
        conn.close()
        return jsonify({'error': 'Not authorized'}), 403

    completed_date = None
    if new_status == 'completed':
        completed_date = datetime.datetime.now().isoformat()
        try:
            txid = record_group_task_on_chain(group_id, task_id, user['id'])
        except Exception as e:
            conn.close()
            return jsonify({'error': 'Blockchain recording failed'}), 500
    else:
        txid = None

    conn.execute('''UPDATE group_tasks
                   SET status = ?, completed_date = ?, tx_id = ?
                   WHERE id = ?''',
               (new_status, completed_date, txid, task_id))

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'tx_id': txid})

@app.route('/groups/<int:group_id>/task/<int:task_id>', methods=['DELETE'])
def delete_task(group_id, task_id):
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db_connection()

    # Check if user is group lead
    is_lead = conn.execute('SELECT * FROM group_members WHERE group_id = ? AND user_id = ? AND role = "lead"',
                          (group_id, user['id'])).fetchone() is not None

    if not is_lead and user['role'] != 'admin':
        conn.close()
        return jsonify({'error': 'Not authorized'}), 403

    conn.execute('DELETE FROM group_tasks WHERE id = ? AND group_id = ?', (task_id, group_id))
    conn.commit()
    conn.close()

    return jsonify({'success': True})

@app.route('/groups/<int:group_id>/milestone', methods=['POST'])
def create_milestone(group_id):
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db_connection()

    # Check if user is group lead
    is_lead = conn.execute('SELECT * FROM group_members WHERE group_id = ? AND user_id = ? AND role = "lead"',
                          (group_id, user['id'])).fetchone() is not None

    if not is_lead and user['role'] != 'admin':
        conn.close()
        return jsonify({'error': 'Not authorized'}), 403

    title = request.form.get('title')
    description = request.form.get('description')
    target_date = request.form.get('target_date')

    cursor = conn.cursor()
    cursor.execute('''INSERT INTO group_milestones
                     (group_id, title, description, target_date)
                     VALUES (?, ?, ?, ?)''',
                  (group_id, title, description, target_date))
    milestone_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'milestone_id': milestone_id})

@app.route('/groups/<int:group_id>/milestone/<int:milestone_id>/complete', methods=['PUT'])
def complete_milestone(group_id, milestone_id):
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db_connection()

    # Check if user is group lead
    is_lead = conn.execute('SELECT * FROM group_members WHERE group_id = ? AND user_id = ? AND role = "lead"',
                          (group_id, user['id'])).fetchone() is not None

    if not is_lead and user['role'] != 'admin':
        conn.close()
        return jsonify({'error': 'Not authorized'}), 403

    proof_url = request.json.get('proof_url')
    proof_hash = hashlib.sha256(proof_url.encode()).hexdigest() if proof_url else ''
    completed_time = datetime.datetime.now().isoformat()

    try:
        txid = record_group_milestone_on_chain(group_id, milestone_id, proof_hash, completed_time)
    except Exception as e:
        return jsonify({'error': 'Blockchain recording failed'}), 500

    conn.execute('''UPDATE group_milestones
                   SET completed_date = ?, proof_url = ?, tx_id = ?
                   WHERE id = ?''',
               (completed_time, proof_url, txid, milestone_id))

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'tx_id': txid})

@app.route('/admin/transactions')
def admin_transactions():
    user = get_current_user()
    if not user or user['role'] != 'admin':
        flash('Unauthorized')
        return redirect(url_for('dashboard'))
        
    conn = get_db_connection()
    # Join with users to get names
    logs = conn.execute('''
        SELECT t.*, u.name as user_name 
        FROM transaction_logs t 
        LEFT JOIN users u ON t.user_id = u.id 
        ORDER BY t.timestamp DESC''').fetchall()
    conn.close()
    
    return render_template('admin_transactions.html', logs=logs)

@app.route('/wallet')
def wallet_features():
    return render_template('wallet_features.html')

@app.route('/wallet/pay', methods=['POST'])
def wallet_pay():
    receiver = request.form.get('receiver')
    amount = request.form.get('amount')
    note = request.form.get('note', '')
    
    result = send_algo_payment(receiver, amount, note)
    
    if result['success']:
        flash(f'Payment Sent! TX ID: {result["tx_id"]}', 'success')
    else:
        flash(f'Payment Failed: {result.get("error")}', 'danger')
        
    return redirect(url_for('wallet_features'))

@app.route('/wallet/create_asset', methods=['POST'])
def wallet_create_asset():
    unit_name = request.form.get('unit_name')
    asset_name = request.form.get('asset_name')
    total = request.form.get('total')
    decimals = request.form.get('decimals')
    url = request.form.get('url')
    
    result = create_asa(unit_name, asset_name, total, decimals, url)
    
    if result['success']:
        flash(f'Asset Created! ID: {result["asset_id"]} (TX: {result["tx_id"]})', 'success')
    else:
        flash(f'Asset Creation Failed: {result.get("error")}', 'danger')
        
    return redirect(url_for('wallet_features'))

@app.route('/wallet/mint_nft', methods=['POST'])
def wallet_mint_nft():
    unit_name = request.form.get('unit_name')
    asset_name = request.form.get('asset_name')
    ipfs_url = request.form.get('ipfs_url')
    
    result = mint_nft(unit_name, asset_name, ipfs_url)
    
    if result['success']:
        flash(f'NFT Minted! ID: {result["asset_id"]} (TX: {result["tx_id"]})', 'success')
    else:
        flash(f'NFT Minting Failed: {result.get("error")}', 'danger')
        
    return redirect(url_for('wallet_features'))

@app.route('/wallet/contract/deploy', methods=['POST'])
def wallet_contract_deploy():
    if not approval_program or not clear_state_program:
        flash('Smart Contract features unavailable (PyTeal missing?)', 'danger')
        return redirect(url_for('wallet_features'))

    try:
        # Get TEAL source
        approval_teal = approval_program()
        clear_teal = clear_state_program()
        
        result = deploy_smart_contract(approval_teal, clear_teal)
        
        if result['success']:
            flash(f'Contract Deployed! App ID: {result["app_id"]} (TX: {result["tx_id"]})', 'success')
        else:
            flash(f'Deployment Failed: {result.get("error")}', 'danger')
            
    except Exception as e:
        flash(f'Compilation/Deployment Error: {str(e)}', 'danger')
        
    return redirect(url_for('wallet_features'))

@app.route('/wallet/contract/interact', methods=['POST'])
def wallet_contract_interact():
    app_id = int(request.form.get('app_id'))
    action = request.form.get('action')
    amount = request.form.get('amount')
    
    result = {'success': False, 'error': 'Invalid Action'}
    
    if action == 'deposit':
        result = call_bank_deposit(app_id, amount)
    elif action == 'withdraw':
        result = call_bank_withdraw(app_id, amount)
        
    if result['success']:
        flash(f'Action {action.upper()} Successful! TX: {result["tx_id"]}', 'success')
    else:
        flash(f'Action Failed: {result.get("error")}', 'danger')
        
    return redirect(url_for('wallet_features'))

    return redirect(url_for('wallet_features'))

@app.route('/wallet/contract/history', methods=['POST'])
def wallet_contract_history():
    app_id = int(request.form.get('app_id'))
    result = get_contract_history(app_id)
    
    if result['success']:
        return render_template('wallet_features.html', contract_history=result['history'], app_id=app_id)
    else:
        flash(f'Failed to fetch history: {result.get("error")}', 'danger')
        return redirect(url_for('wallet_features'))

if __name__ == '__main__':
    app.run(debug=True)