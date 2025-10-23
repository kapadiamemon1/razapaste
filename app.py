from flask import Flask, render_template, request, redirect, url_for, Response, session, flash
import sqlite3
import uuid
from datetime import datetime, timedelta
import html
import os
import hashlib
import secrets

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'
DATABASE = 'raza_paste.db'

def init_db():
    """Initialize the database"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Pastes table with user association
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pastes (
            id TEXT PRIMARY KEY,
            title TEXT,
            content TEXT NOT NULL,
            syntax TEXT DEFAULT 'text',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            view_count INTEGER DEFAULT 0,
            user_id INTEGER,
            is_public BOOLEAN DEFAULT TRUE,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stats (
            key TEXT PRIMARY KEY,
            value INTEGER DEFAULT 0
        )
    ''')
    
    # Initialize total pastes count if not exists
    cursor.execute('INSERT OR IGNORE INTO stats (key, value) VALUES (?, ?)', ('total_pastes', 0))
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    """Hash a password for storing"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    return stored_password == hashlib.sha256(provided_password.encode()).hexdigest()

def calculate_expiration(expiration_option):
    """Calculate expiration datetime based on option"""
    now = datetime.now()
    if expiration_option == 'never':
        return None
    elif expiration_option == '10min':
        return now + timedelta(minutes=10)
    elif expiration_option == '1hour':
        return now + timedelta(hours=1)
    elif expiration_option == '1day':
        return now + timedelta(days=1)
    elif expiration_option == '1week':
        return now + timedelta(weeks=1)
    elif expiration_option == '1month':
        return now + timedelta(days=30)
    return None

def cleanup_expired_pastes():
    """Remove expired pastes"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM pastes WHERE expires_at IS NOT NULL AND expires_at < datetime('now')")
    conn.commit()
    conn.close()

def get_total_pastes_count():
    """Get total pastes count"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM stats WHERE key = 'total_pastes'")
    result = cursor.fetchone()
    conn.close()
    return result['value'] if result else 0

def increment_total_pastes():
    """Increment total pastes count"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE stats SET value = value + 1 WHERE key = 'total_pastes'")
    conn.commit()
    conn.close()

def get_user_pastes_count(user_id):
    """Get pastes count for a specific user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as count FROM pastes WHERE user_id = ?", (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result['count'] if result else 0

# Authentication required decorator
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Home page - create new paste"""
    total_pastes = get_total_pastes_count()
    user_pastes_count = get_user_pastes_count(session.get('user_id')) if 'user_id' in session else 0
    return render_template('index.html', total_pastes=total_pastes, user_pastes_count=user_pastes_count)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not username or not email or not password:
            flash('All fields are required!', 'error')
            return render_template('signup.html')
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('signup.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return render_template('signup.html')
        
        password_hash = hash_password(password)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                (username, email, password_hash)
            )
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists!', 'error')
            return render_template('signup.html')
        finally:
            conn.close()
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please enter both username and password!', 'error')
            return render_template('login.html')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, username))
        user = cursor.fetchone()
        conn.close()
        
        if user and verify_password(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password!', 'error')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/create', methods=['POST'])
@login_required
def create_paste():
    """Create a new paste"""
    content = request.form.get('content', '').strip()
    title = request.form.get('title', '').strip()
    syntax = request.form.get('syntax', 'text')
    expiration = request.form.get('expiration', 'never')
    is_public = request.form.get('is_public', 'true') == 'true'
    
    if not content:
        flash('Paste content cannot be empty!', 'error')
        return render_template('index.html', content=content)
    
    # Generate unique ID
    paste_id = str(uuid.uuid4())[:8]
    expires_at = calculate_expiration(expiration)
    
    # Save to database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO pastes (id, title, content, syntax, expires_at, user_id, is_public)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (paste_id, title, content, syntax, expires_at, session['user_id'], is_public))
    conn.commit()
    conn.close()
    
    # Update statistics
    increment_total_pastes()
    
    # Clean up expired pastes
    cleanup_expired_pastes()
    
    flash('Paste created successfully!', 'success')
    return redirect(url_for('view_paste', paste_id=paste_id))

@app.route('/paste/<paste_id>')
def view_paste(paste_id):
    """View a specific paste - public pastes accessible via direct URL"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT p.*, u.username 
        FROM pastes p 
        LEFT JOIN users u ON p.user_id = u.id 
        WHERE p.id = ?
    ''', (paste_id,))
    
    paste = cursor.fetchone()
    conn.close()
    
    if not paste:
        flash('Paste not found or has expired!', 'error')
        return redirect(url_for('index'))
    
    # Check if paste is expired
    if paste['expires_at']:
        expires_at = datetime.fromisoformat(paste['expires_at'])
        if expires_at < datetime.now():
            # Delete expired paste
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('DELETE FROM pastes WHERE id = ?', (paste_id,))
            conn.commit()
            conn.close()
            flash('Paste has expired!', 'error')
            return redirect(url_for('index'))
    
    # Check if user can view this paste
    # Allow access if: paste is public OR user owns the paste
    if not paste['is_public'] and ('user_id' not in session or paste['user_id'] != session['user_id']):
        flash('You do not have permission to view this paste!', 'error')
        return redirect(url_for('index'))
    
    # Convert to dict for template
    paste_dict = {
        'id': paste['id'],
        'title': paste['title'],
        'content': paste['content'],
        'syntax': paste['syntax'],
        'created_at': datetime.fromisoformat(paste['created_at']),
        'expires_at': datetime.fromisoformat(paste['expires_at']) if paste['expires_at'] else None,
        'view_count': paste['view_count'],
        'username': paste['username'],
        'is_public': paste['is_public']
    }
    
    total_pastes = get_total_pastes_count()
    user_pastes_count = get_user_pastes_count(session.get('user_id')) if 'user_id' in session else 0
    return render_template('view_paste.html', paste=paste_dict, total_pastes=total_pastes, user_pastes_count=user_pastes_count)

@app.route('/raw/<paste_id>')
def raw_paste(paste_id):
    """View raw paste content"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT content, is_public, user_id FROM pastes WHERE id = ?', (paste_id,))
    paste = cursor.fetchone()
    conn.close()
    
    if not paste:
        return "Paste not found or has expired!", 404
    
    # Check permissions
    if not paste['is_public'] and ('user_id' not in session or paste['user_id'] != session['user_id']):
        return "Access denied!", 403
    
    response = Response(paste['content'], mimetype='text/plain')
    response.headers['Content-Disposition'] = f'inline; filename="{paste_id}.txt"'
    return response

@app.route('/download/<paste_id>')
def download_paste(paste_id):
    """Download paste as text file"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT content, title, is_public, user_id FROM pastes WHERE id = ?', (paste_id,))
    paste = cursor.fetchone()
    conn.close()
    
    if not paste:
        return "Paste not found or has expired!", 404
    
    # Check permissions
    if not paste['is_public'] and ('user_id' not in session or paste['user_id'] != session['user_id']):
        return "Access denied!", 403
    
    filename = f"{paste['title'] or 'paste'}_{paste_id}.txt".replace(' ', '_')
    response = Response(paste['content'], mimetype='text/plain')
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response

@app.route('/recent')
def list_pastes():
    """List user's own pastes (if logged in) or show empty state"""
    cleanup_expired_pastes()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if 'user_id' in session:
        # Show only user's own pastes
        cursor.execute('''
            SELECT p.*, u.username 
            FROM pastes p 
            LEFT JOIN users u ON p.user_id = u.id 
            WHERE p.user_id = ?
            ORDER BY p.created_at DESC 
            LIMIT 50
        ''', (session['user_id'],))
    else:
        # Show empty state for logged-out users
        pastes = []
        conn.close()
        total_pastes = get_total_pastes_count()
        return render_template('list_pastes.html', pastes=pastes, total_pastes=total_pastes, user_pastes_count=0)
    
    pastes = []
    for row in cursor.fetchall():
        pastes.append({
            'id': row['id'],
            'title': row['title'],
            'content': row['content'],
            'syntax': row['syntax'],
            'created_at': datetime.fromisoformat(row['created_at']),
            'expires_at': datetime.fromisoformat(row['expires_at']) if row['expires_at'] else None,
            'view_count': row['view_count'],
            'username': row['username'],
            'is_public': row['is_public']
        })
    
    conn.close()
    total_pastes = get_total_pastes_count()
    user_pastes_count = get_user_pastes_count(session.get('user_id')) if 'user_id' in session else 0
    return render_template('list_pastes.html', pastes=pastes, total_pastes=total_pastes, user_pastes_count=user_pastes_count)

@app.route('/my-pastes')
@login_required
def my_pastes():
    """List user's pastes"""
    cleanup_expired_pastes()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM pastes 
        WHERE user_id = ?
        ORDER BY created_at DESC 
        LIMIT 50
    ''', (session['user_id'],))
    
    pastes = []
    for row in cursor.fetchall():
        pastes.append({
            'id': row['id'],
            'title': row['title'],
            'content': row['content'],
            'syntax': row['syntax'],
            'created_at': datetime.fromisoformat(row['created_at']),
            'expires_at': datetime.fromisoformat(row['expires_at']) if row['expires_at'] else None,
            'view_count': row['view_count'],
            'is_public': row['is_public']
        })
    
    conn.close()
    total_pastes = get_total_pastes_count()
    user_pastes_count = get_user_pastes_count(session['user_id'])
    return render_template('my_pastes.html', pastes=pastes, total_pastes=total_pastes, user_pastes_count=user_pastes_count)

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)