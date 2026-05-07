"""
MindView Virtual Classroom — Flask backend with role-based user management.
Roles: superuser, admin, teacher, student
Run: python app.py
First run: prompts to create the initial Super User.
"""
import os, sqlite3, secrets, sys
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from flask import (Flask, request, render_template, redirect, url_for,
                   session, flash, jsonify, send_from_directory, abort, g)
from werkzeug.security import generate_password_hash, check_password_hash

# ---------- Configuration ----------
ROOT = Path(__file__).parent.resolve()
DB_PATH = ROOT / "users.db"
SECRET_KEY_FILE = ROOT / ".secret_key"

app = Flask(__name__, template_folder=str(ROOT / "templates"), static_folder=None)

# Persistent secret key (so sessions survive restarts)
if SECRET_KEY_FILE.exists():
    app.secret_key = SECRET_KEY_FILE.read_bytes()
else:
    app.secret_key = secrets.token_bytes(32)
    SECRET_KEY_FILE.write_bytes(app.secret_key)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,  # 8 hours
)

# ---------- DEV MODE ----------
# When True AND the request is from localhost (127.0.0.1 / ::1), automatically
# log in as the Super User. This is for local development only — set to False
# (or unset MINDVIEW_DEV env var) when deploying to a public server.
#
# Disable: set environment variable MINDVIEW_DEV=0 before running, or change
# the default below to False.
DEV_MODE = os.environ.get('MINDVIEW_DEV', '1') != '0'
LOOPBACK_IPS = {'127.0.0.1', '::1', 'localhost'}

ROLES = ['superuser', 'admin', 'teacher', 'student']
ROLE_LABELS = {
    'superuser': 'Super User',
    'admin': 'Administrator',
    'teacher': 'Teacher',
    'student': 'Student',
}

# ---------- Database ----------
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db: db.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('superuser','admin','teacher','student')),
        full_name TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        last_login TEXT,
        created_by INTEGER REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_id INTEGER REFERENCES users(id),
        actor_username TEXT,
        action TEXT NOT NULL,
        target_user_id INTEGER,
        target_username TEXT,
        details TEXT,
        timestamp TEXT NOT NULL,
        ip TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id);
    CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);
    """)
    conn.commit()
    conn.close()

def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def log_action(actor_id, actor_username, action, target_user_id=None, target_username=None, details=None):
    db = get_db()
    db.execute(
        "INSERT INTO audit_log(actor_id, actor_username, action, target_user_id, target_username, details, timestamp, ip) VALUES (?,?,?,?,?,?,?,?)",
        (actor_id, actor_username, action, target_user_id, target_username, details, now_iso(), request.remote_addr if request else None)
    )
    db.commit()

# ---------- Dev Mode auto-login (localhost only) ----------
@app.before_request
def auto_dev_login():
    """When DEV_MODE is on and request is from localhost, auto-login as Super User.
    Skips API auth endpoints so explicit logins still work. Skips static assets."""
    if not DEV_MODE:
        return
    if request.remote_addr not in LOOPBACK_IPS:
        return
    # Don't intercept the auth API itself
    if request.path.startswith('/api/auth/'):
        return
    if session.get('user_id'):
        return  # Already logged in
    # Find the first active super user and create a session
    try:
        db = get_db()
        su = db.execute(
            "SELECT id FROM users WHERE role = 'superuser' AND active = 1 ORDER BY id LIMIT 1"
        ).fetchone()
        if su:
            session.permanent = True
            session['user_id'] = su['id']
            session['_dev_auto'] = True  # Marker so UI can show a dev-mode banner
    except Exception:
        # If DB isn't ready yet, fall through to normal auth
        pass

# ---------- Auth helpers ----------
def current_user():
    uid = session.get('user_id')
    if not uid: return None
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ? AND active = 1", (uid,)).fetchone()
    return dict(row) if row else None

def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not current_user():
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login_page', next=request.path))
        return f(*a, **kw)
    return wrapper

def role_required(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            u = current_user()
            if not u:
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Authentication required'}), 401
                return redirect(url_for('login_page'))
            if u['role'] not in roles:
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Insufficient permissions'}), 403
                return render_template('admin/403.html', user=u), 403
            return f(*a, **kw)
        return wrapper
    return deco

def can_manage_role(actor_role, target_role):
    """Returns True if actor_role can create/edit/delete a user with target_role."""
    if actor_role == 'superuser':
        return True
    if actor_role == 'admin':
        # Admins manage teachers and students; NOT other admins or superusers
        return target_role in ('teacher', 'student')
    return False

# ---------- Routes: Public ----------
@app.route('/login', methods=['GET'])
def login_page():
    if current_user():
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/login.html', next=request.args.get('next', '/'))

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE (username = ? OR email = ?) AND active = 1", (username, username)).fetchone()
    if not row or not check_password_hash(row['password_hash'], password):
        # Don't reveal which one was wrong
        log_action(None, username, 'login_failed', details='Invalid credentials')
        return jsonify({'error': 'Invalid username or password'}), 401
    session.permanent = True
    session['user_id'] = row['id']
    db.execute("UPDATE users SET last_login = ? WHERE id = ?", (now_iso(), row['id']))
    db.commit()
    log_action(row['id'], row['username'], 'login_success')
    return jsonify({'ok': True, 'user': {'username': row['username'], 'role': row['role'], 'full_name': row['full_name']}})

@app.route('/api/me', methods=['GET'])
def api_me():
    """Return current user info — used by static HTML pages to show role-based UI."""
    u = current_user()
    if not u:
        return jsonify({'authenticated': False}), 200
    return jsonify({
        'authenticated': True,
        'dev_mode': bool(session.get('_dev_auto')),
        'user': {
            'id': u['id'],
            'username': u['username'],
            'full_name': u['full_name'],
            'role': u['role'],
            'role_label': ROLE_LABELS[u['role']],
            'can_manage_users': u['role'] in ('superuser', 'admin'),
        }
    })

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    u = current_user()
    if u:
        log_action(u['id'], u['username'], 'logout')
    session.clear()
    return jsonify({'ok': True})

@app.route('/logout')
def logout_redirect():
    u = current_user()
    if u:
        log_action(u['id'], u['username'], 'logout')
    session.clear()
    return redirect(url_for('login_page'))

# ---------- Routes: Admin Panel ----------
@app.route('/admin')
@login_required
def admin_dashboard():
    u = current_user()
    db = get_db()
    stats = {
        'total_users': db.execute("SELECT COUNT(*) c FROM users WHERE active = 1").fetchone()['c'],
        'by_role': {r: db.execute("SELECT COUNT(*) c FROM users WHERE role = ? AND active = 1", (r,)).fetchone()['c'] for r in ROLES},
    }
    recent_logins = db.execute(
        "SELECT username, full_name, role, last_login FROM users WHERE last_login IS NOT NULL AND active = 1 ORDER BY last_login DESC LIMIT 10"
    ).fetchall()
    return render_template('admin/dashboard.html', user=u, stats=stats, recent_logins=recent_logins, role_labels=ROLE_LABELS)

@app.route('/admin/users')
@role_required('superuser', 'admin')
def admin_users():
    u = current_user()
    db = get_db()
    if u['role'] == 'superuser':
        users = db.execute("SELECT * FROM users ORDER BY role, username").fetchall()
    else:
        # Admins see only teachers + students (and themselves)
        users = db.execute("SELECT * FROM users WHERE role IN ('teacher','student') OR id = ? ORDER BY role, username", (u['id'],)).fetchall()
    return render_template('admin/users.html', user=u, users=users, role_labels=ROLE_LABELS, can_manage_role=can_manage_role)

@app.route('/admin/audit')
@role_required('superuser', 'admin')
def admin_audit():
    u = current_user()
    db = get_db()
    entries = db.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 200").fetchall()
    return render_template('admin/audit.html', user=u, entries=entries)

# ---------- API: User CRUD ----------
@app.route('/api/users', methods=['GET'])
@role_required('superuser', 'admin')
def api_list_users():
    u = current_user()
    db = get_db()
    if u['role'] == 'superuser':
        rows = db.execute("SELECT id, username, email, role, full_name, active, created_at, last_login FROM users ORDER BY id").fetchall()
    else:
        rows = db.execute("SELECT id, username, email, role, full_name, active, created_at, last_login FROM users WHERE role IN ('teacher','student') ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/users', methods=['POST'])
@role_required('superuser', 'admin')
def api_create_user():
    u = current_user()
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip().lower()
    email = (data.get('email') or '').strip().lower()
    full_name = (data.get('full_name') or '').strip()
    role = data.get('role')
    password = data.get('password') or ''
    if not all([username, email, full_name, role, password]):
        return jsonify({'error': 'All fields required'}), 400
    if role not in ROLES:
        return jsonify({'error': 'Invalid role'}), 400
    if not can_manage_role(u['role'], role):
        return jsonify({'error': f'Your role cannot create {ROLE_LABELS[role]} users'}), 403
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO users(username, email, password_hash, role, full_name, created_at, created_by) VALUES (?,?,?,?,?,?,?)",
            (username, email, generate_password_hash(password), role, full_name, now_iso(), u['id'])
        )
        db.commit()
    except sqlite3.IntegrityError as e:
        return jsonify({'error': 'Username or email already exists'}), 409
    log_action(u['id'], u['username'], 'create_user', cur.lastrowid, username, f'role={role}')
    return jsonify({'ok': True, 'id': cur.lastrowid})

@app.route('/api/users/<int:user_id>', methods=['PATCH'])
@role_required('superuser', 'admin')
def api_update_user(user_id):
    u = current_user()
    if u['id'] == user_id:
        return jsonify({'error': 'Cannot edit your own account here — use Profile'}), 400
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target:
        return jsonify({'error': 'User not found'}), 404
    if not can_manage_role(u['role'], target['role']):
        return jsonify({'error': 'Insufficient permissions'}), 403
    data = request.get_json(silent=True) or {}
    fields = []
    values = []
    if 'full_name' in data:
        fields.append('full_name = ?'); values.append(data['full_name'].strip())
    if 'email' in data:
        fields.append('email = ?'); values.append(data['email'].strip().lower())
    if 'active' in data:
        fields.append('active = ?'); values.append(1 if data['active'] else 0)
    if 'role' in data:
        new_role = data['role']
        if new_role not in ROLES:
            return jsonify({'error': 'Invalid role'}), 400
        if not can_manage_role(u['role'], new_role):
            return jsonify({'error': f'Cannot promote to {ROLE_LABELS[new_role]}'}), 403
        fields.append('role = ?'); values.append(new_role)
    if 'password' in data:
        if len(data['password']) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        fields.append('password_hash = ?'); values.append(generate_password_hash(data['password']))
    if not fields:
        return jsonify({'error': 'Nothing to update'}), 400
    values.append(user_id)
    db.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", values)
    db.commit()
    log_action(u['id'], u['username'], 'update_user', user_id, target['username'], ','.join(f.split(' = ')[0] for f in fields))
    return jsonify({'ok': True})

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@role_required('superuser', 'admin')
def api_delete_user(user_id):
    u = current_user()
    if u['id'] == user_id:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target:
        return jsonify({'error': 'User not found'}), 404
    if not can_manage_role(u['role'], target['role']):
        return jsonify({'error': 'Insufficient permissions'}), 403
    # Soft delete (deactivate). Use ?hard=1 for hard delete (superuser only)
    if request.args.get('hard') == '1':
        if u['role'] != 'superuser':
            return jsonify({'error': 'Only Super User can hard-delete'}), 403
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        action = 'hard_delete_user'
    else:
        db.execute("UPDATE users SET active = 0 WHERE id = ?", (user_id,))
        action = 'deactivate_user'
    db.commit()
    log_action(u['id'], u['username'], action, user_id, target['username'])
    return jsonify({'ok': True})

# ---------- Static file serving (with auth gate) ----------
PUBLIC_PATHS = {'/login', '/logout', '/static/admin.css'}
PUBLIC_PREFIXES = ('/api/auth/', '/css/', '/templates/')

@app.route('/')
@app.route('/<path:filename>')
def serve_static(filename='index.html'):
    # Public assets (CSS, login)
    full_path = ROOT / filename
    if filename.endswith('.css') or filename == 'logo.png':
        if full_path.exists():
            return send_from_directory(str(ROOT), filename)
    # Auth gate for everything else
    if not current_user():
        return redirect(url_for('login_page', next='/' + filename))
    # Block access to sensitive files
    if filename.startswith(('.', 'app.py', 'users.db', '.secret_key')):
        abort(404)
    if not full_path.exists() or full_path.is_dir():
        abort(404)
    return send_from_directory(str(ROOT), filename)

# ---------- CLI: bootstrap super user ----------
def bootstrap():
    """Called on first launch if no superuser exists."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    su = conn.execute("SELECT id FROM users WHERE role = 'superuser' AND active = 1").fetchone()
    if su:
        conn.close()
        return
    print("\n" + "=" * 60)
    print("  MindView — First-time Super User Setup")
    print("=" * 60)
    print("No Super User found. Create one now.")
    username = input("  Username: ").strip().lower()
    email = input("  Email: ").strip().lower()
    full_name = input("  Full name: ").strip()
    while True:
        import getpass
        password = getpass.getpass("  Password (min 8 chars): ")
        if len(password) >= 8:
            confirm = getpass.getpass("  Confirm password: ")
            if password == confirm:
                break
            print("  Passwords don't match. Try again.")
        else:
            print("  Password too short.")
    conn.execute(
        "INSERT INTO users(username, email, password_hash, role, full_name, created_at) VALUES (?,?,?,?,?,?)",
        (username, email, generate_password_hash(password), 'superuser', full_name, now_iso())
    )
    conn.commit()
    conn.close()
    print(f"\n  ✅ Super User '{username}' created. You can now log in.\n")

if __name__ == '__main__':
    bootstrap()
    print("\n" + "=" * 60)
    print("  MindView Virtual Classroom")
    print("=" * 60)
    if DEV_MODE:
        print("  *** DEV MODE *** Auto-login enabled for localhost (127.0.0.1)")
        print("  -> Open: http://localhost:3000/  (no login needed locally)")
        print("  -> External IPs will still require credentials")
        print("  -> To disable: set environment variable MINDVIEW_DEV=0")
    else:
        print("  Production mode - all users must authenticate")
        print("  -> Open: http://localhost:3000/login")
    print("=" * 60 + "\n")
    app.run(host='127.0.0.1', port=3000, debug=False)
