from flask import Flask, request, render_template, redirect, url_for, send_file, session, jsonify, abort, Response
import os
import re
import requests
import urllib.parse
import socket
import mimetypes
import time
import sqlite3
import hashlib
import secrets
import ipaddress
from functools import wraps
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "super_secret_key_for_ctf_challenge"


UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
FLAG = "BMCTF{LOCALHOST_isnt_ALWAYS_local}"
DATABASE = 'ctf_challenge.db'


os.makedirs(UPLOAD_FOLDER, exist_ok=True)


os.makedirs('/var/flag', exist_ok=True)
with open('/var/flag/flag.txt', 'w') as f:
    f.write(FLAG)

# Database setup functions
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        profile_pic TEXT NOT NULL
    )
    ''')
    
    # Create default admin and user accounts if they don't exist
    admin_exists = cursor.execute("SELECT 1 FROM users WHERE username = ?", ("admin",)).fetchone()
    if not admin_exists:
        admin_password_hash = hashlib.sha256("admin_super_secret_password".encode()).hexdigest()
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, profile_pic) VALUES (?, ?, ?, ?)",
            ("admin", admin_password_hash, "admin", "default.jpg")
        )
    
    user_exists = cursor.execute("SELECT 1 FROM users WHERE username = ?", ("user",)).fetchone()
    if not user_exists:
        user_password_hash = hashlib.sha256("user123".encode()).hexdigest()
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, profile_pic) VALUES (?, ?, ?, ?)",
            ("user", user_password_hash, "user", "default.jpg")
        )
    
    conn.commit()
    conn.close()

# Helper Functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def resolve_hostname(host):
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        return None

def normalize_hostname(host):
    """Normalize hostname to catch various encoding tricks"""
    # Remove brackets for IPv6
    host = host.strip('[]')
    
    # URL decode multiple times to catch double encoding
    prev_host = None
    while prev_host != host:
        prev_host = host
        try:
            host = urllib.parse.unquote(host)
        except:
            break
    
    return host.lower()

def is_localhost_variant(host):
    """Check for localhost variants and representations"""
    normalized = normalize_hostname(host)
    
    # Direct localhost checks
    localhost_variants = [
        'localhost', 'local', '127.0.0.1', '::1', '0:0:0:0:0:0:0:1'
    ]
    
    for variant in localhost_variants:
        if normalized == variant:
            return True
    
    # Check for 127.x.x.x range (entire Class A loopback)
    if re.match(r'^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$', normalized):
        return True
    
    # IPv6 localhost variants
    ipv6_localhost = [
        '::1', '0:0:0:0:0:0:0:1', '0000:0000:0000:0000:0000:0000:0000:0001',
        '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:7f00:0001',
        '0:0:0:0:0:ffff:127.0.0.1', '0:0:0:0:0:ffff:7f00:1', '0:0:0:0:0:ffff:7f00:0001'
    ]
    
    for variant in ipv6_localhost:
        if normalized == variant:
            return True
    
    # Alternative IP representations
    try:
        # Decimal representation (2130706433 = 127.0.0.1)
        if normalized.isdigit():
            decimal_val = int(normalized)
            if decimal_val == 2130706433:
                return True
        
        # Octal representations
        if re.match(r'^0[0-7]+$', normalized):
            try:
                decimal_val = int(normalized, 8)
                if decimal_val == 2130706433:
                    return True
            except ValueError:
                pass
        
        # Hex representations
        if normalized.startswith('0x'):
            try:
                decimal_val = int(normalized, 16)
                if decimal_val == 2130706433:
                    return True
            except ValueError:
                pass
        
        # Mixed representations like 127.1, 127.0.1
        if re.match(r'^127\.\d+$', normalized) or re.match(r'^127\.0\.\d+$', normalized):
            return True
            
    except:
        pass
    
    return False

def is_private_ip(ip_str):
    """Check if IP is in private ranges"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast or ip.is_link_local
    except ValueError:
        return False

def is_internal_ip(host):
    """Comprehensive check for internal/private IPs"""
    normalized_host = normalize_hostname(host)
    
    # Check for localhost variants first
    if is_localhost_variant(normalized_host):
        return True
    
    # Try to resolve hostname
    resolved_ip = resolve_hostname(normalized_host)
    
    # If it resolves, check the resolved IP
    if resolved_ip:
        if is_private_ip(resolved_ip):
            return True
        
        # Additional check for resolved localhost
        if is_localhost_variant(resolved_ip):
            return True
    
    # If hostname doesn't resolve, treat it as potential IP and check
    if not resolved_ip:
        if is_private_ip(normalized_host):
            return True
    
    # Check for private network patterns in hostname itself
    private_patterns = [
        r'^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
        r'^172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}$',
        r'^192\.168\.\d{1,3}\.\d{1,3}$',
        r'^169\.254\.\d{1,3}\.\d{1,3}$',  # Link local
        r'^0\.\d{1,3}\.\d{1,3}\.\d{1,3}$',  # 0.x.x.x range
    ]
    
    for pattern in private_patterns:
        if re.match(pattern, normalized_host):
            return True
    
    # Check for IPv6 private patterns
    if ':' in normalized_host:
        ipv6_private_patterns = [
            r'^fe80:',  # Link local
            r'^fc00:',  # Unique local
            r'^fd00:',  # Unique local
            r'^ff00:',  # Multicast
        ]
        
        for pattern in ipv6_private_patterns:
            if re.match(pattern, normalized_host):
                return True
    
    # Block common bypass domains that aren't real DNS rebinding
    suspicious_domains = [
        'localtest.me', 'lvh.me', 'vcap.me', 'lacolhost.com',
        '127.0.0.1.nip.io', 'localhost.localdomain'
    ]
    
    for domain in suspicious_domains:
        if domain in normalized_host:
            return True
    
    return False

def get_user(username):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return user if user else None

def authenticate_user(username, password):
    user = get_user(username)
    if user:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if password_hash == user['password_hash']:
            return user
    return None

# Decorators for access control
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if request is coming from localhost (127.0.0.1)
        if request.remote_addr == '127.0.0.1':
            return f(*args, **kwargs)

        # Otherwise, enforce admin session
        if 'user_id' in session:
            conn = get_db_connection()
            user = conn.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],)).fetchone()
            conn.close()
            
            if user and user['role'] == 'admin':
                return f(*args, **kwargs)

        # Not localhost and not admin → deny
        return "Forbidden", 403
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        conn.close()
        
        if user:
            return render_template('index.html', 
                                  username=user['username'], 
                                  profile_pic=user['profile_pic'], 
                                  role=user['role'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = authenticate_user(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))
        error = "Invalid credentials"
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            error = "Username and password are required"
        elif len(username) < 3 or len(password) < 4:
            error = "Username must be at least 3 characters and password at least 4 characters"
        else:
            conn = get_db_connection()
            user_exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
            
            if user_exists:
                error = "Username already exists"
            else:
                # Hash the password and create new user with default role
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                
                try:
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO users (username, password_hash, role, profile_pic) VALUES (?, ?, ?, ?)",
                        (username, password_hash, "user", "default.jpg")
                    )
                    conn.commit()
                    user_id = cursor.lastrowid
                    session['user_id'] = user_id
                    session['username'] = username
                    conn.close()
                    return redirect(url_for('index'))
                except sqlite3.Error as e:
                    conn.rollback()
                    error = f"Database error: {str(e)}"
                finally:
                    conn.close()
    
    return render_template('register.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn.close()
    
    if not user:
        return redirect(url_for('logout'))
        
    return render_template('profile.html', username=user['username'], profile_pic=user['profile_pic'])

@app.route('/update_profile_pic', methods=['POST'])
@login_required
def update_profile_pic():
    error = None
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    
    if not user:
        conn.close()
        return redirect(url_for('logout'))
    
    if 'file' in request.files and request.files['file'].filename:
        file = request.files['file']
        if file and allowed_file(file.filename):
            # Generate a unique filename to prevent overwriting
            filename = secure_filename(file.filename)
            filename = f"{int(time.time())}_{filename}"
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            
            conn.execute("UPDATE users SET profile_pic = ? WHERE id = ?", (filename, session['user_id']))
            conn.commit()
            conn.close()
            return redirect(url_for('profile'))
        else:
            error = "Invalid file or file type"

    elif 'image_url' in request.form and request.form['image_url']:
        url = request.form['image_url']

        # Validate URL format - must start with http:// or https://
        if not url.startswith('http://') and not url.startswith('https://'):
            conn.close()
            return render_template('profile.html', username=user['username'],
                                  profile_pic=user['profile_pic'],
                                  error="Invalid URL. URL must start with http:// or https://")

        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.netloc.split(':')[0].lower()

        # Block non-standard ports that might be used for internal services
        if parsed_url.port:
            dangerous_ports = [22, 23, 25, 53, 135, 139, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5984, 6379, 8080, 9200, 27017]
            if parsed_url.port in dangerous_ports:
                conn.close()
                return render_template('profile.html', username=user['username'], 
                                      profile_pic=user['profile_pic'],
                                      error="Error: Cannot use restricted ports")

        if is_internal_ip(hostname):
            conn.close()
            return render_template('profile.html', username=user['username'], 
                                  profile_pic=user['profile_pic'],
                                  error="Error: Cannot use internal URLs")
        
        try:
            # Add some headers to make request look more legitimate
            headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(url, timeout=5, headers=headers, allow_redirects=False)
            if response.status_code == 200:
                # Accept any response as an image
                filename = f"url_image_{user['username']}_{int(time.time())}.jpg"
                filepath = os.path.join(UPLOAD_FOLDER, filename)
                with open(filepath, 'wb') as f:
                    f.write(response.content)
                
                conn.execute("UPDATE users SET profile_pic = ? WHERE id = ?", (filename, session['user_id']))
                conn.commit()
                conn.close()
                return redirect(url_for('profile'))
            else:
                error = f"Could not fetch image (Status code: {response.status_code})"
        except requests.RequestException:
            error = "Failed to connect to the remote server"
        except Exception as e:
            error = f"An unexpected error occurred: {str(e)}"
    else:
        error = "No file or URL provided"

    conn.close()
    return render_template('profile.html', username=user['username'], profile_pic=user['profile_pic'], error=error)

@app.route('/admin')
@admin_required
def admin_panel():
    files = os.listdir(UPLOAD_FOLDER)
    
    # Get all users for admin panel
    conn = get_db_connection()
    users = conn.execute("SELECT id, username, role, profile_pic FROM users").fetchall()
    conn.close()
    
    return render_template('admin.html', files=files, users=users)

@app.route('/admin/view_file')
@admin_required
def view_file():
    file_path = request.args.get('file', '')

    # Simple check that blocks literal '../', '..\', and absolute paths
    if '../' in file_path or '..\\'   in file_path or file_path.startswith('/'):
        return "Invalid path. No traversal allowed!", 403

    # Decode AFTER the check - this creates the vulnerability
    # URL encoded traversal sequences like %2e%2e%2f will pass the check
    decoded_path = urllib.parse.unquote(file_path)

    try:
        # Directly join paths with the decoded value
        safe_path = os.path.join(UPLOAD_FOLDER, decoded_path)

        # Extra safety check to ensure we're still in the uploads folder
        # This will block absolute paths but allow URL-encoded relative traversal
        upload_abs_path = os.path.abspath(UPLOAD_FOLDER)
        requested_abs_path = os.path.abspath(safe_path)

        if not requested_abs_path.startswith(upload_abs_path) and '../' not in decoded_path:
            return "Access denied: File must be in uploads directory", 403

        return send_file(safe_path)
    except FileNotFoundError:
        return "File not found", 404
    except PermissionError:
        return "Permission denied", 403
    except Exception:
        return "An error occurred while accessing the file", 500

@app.route('/templates/<template_name>')
def serve_template(template_name):
    return render_template(template_name)

@app.context_processor
def inject_base_template():
    def get_uploads_path(filename):
        return url_for('uploaded_file', filename=filename)
    return {'get_uploads_path': get_uploads_path}

@app.route('/uploads/<filename>') 
def uploaded_file(filename):
    # Special case for default image that everyone can access
    if filename == 'default.jpg':
        return send_file(os.path.join(UPLOAD_FOLDER, filename))
    
    # Check if user is logged in
    if 'user_id' not in session:
        return "Unauthorized", 401
    
    conn = get_db_connection()
    
    # Admin can access all images
    user = conn.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    if user and user['role'] == 'admin':
        conn.close()
        if os.path.exists(os.path.join(UPLOAD_FOLDER, filename)):
            return send_file(os.path.join(UPLOAD_FOLDER, filename))
        return "File not found", 404
    
    # Regular users can only access their own profile picture
    user_image = conn.execute(
        "SELECT profile_pic FROM users WHERE id = ?", 
        (session['user_id'],)
    ).fetchone()
    conn.close()
    
    # Check if the requested image is the user's profile picture
    if user_image and user_image['profile_pic'] == filename:
        if os.path.exists(os.path.join(UPLOAD_FOLDER, filename)):
            return send_file(os.path.join(UPLOAD_FOLDER, filename))
        return "File not found", 404
    
    # If it's not their image and they're not admin, deny access
    return "Access denied", 403

@app.route('/admin/manage_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def manage_user(user_id):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not user:
        conn.close()
        return "User not found", 404
        
    error = None
    success = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_role':
            new_role = request.form.get('role')
            if new_role in ['user', 'admin']:
                conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
                conn.commit()
                success = f"Role updated to {new_role}"
                # Refresh user data
                user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        
        elif action == 'reset_password':
            new_password = secrets.token_urlsafe(10)  # Generate a secure random password
            password_hash = hashlib.sha256(new_password.encode()).hexdigest()
            
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
            conn.commit()
            success = f"Password reset. New password: {new_password}"
            
        elif action == 'delete_user':
            if user['username'] != 'admin':  # Prevent deleting the main admin
                conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
                conn.commit()
                conn.close()
                return redirect(url_for('admin_panel'))
            else:
                error = "Cannot delete the main admin account"
    
    conn.close()
    return render_template('manage_user.html', user=user, error=error, success=success)

@app.route('/search')
@login_required 
def search_users():
    query = request.args.get('q', '') 
    users = [] # Initialize users as an empty list

    # Only perform the database search if a query is provided
    if query:
        # Log the query to make it seem promising for SQLi
        print(f"Searching for: {query}") 
        
        conn = get_db_connection()        
        # Use parameterized query (actually safe)
        users = conn.execute(
            "SELECT username, role FROM users WHERE username LIKE ? LIMIT 5",
            (f"%{query}%",)
        ).fetchall()
        conn.close()        
    
    return render_template('search.html', users=users, query=query)


if __name__ == '__main__':
    default_img_path = os.path.join(UPLOAD_FOLDER, 'default.jpg')
    if not os.path.exists(default_img_path):
        with open(default_img_path, 'wb') as f:
            f.write(b'Default profile image placeholder')

    # Initialize the database
    init_db()
    
    os.makedirs('templates', exist_ok=True)

    # Create base template
    with open('templates/base.html', 'w') as f:
        f.write('''
<!DOCTYPE html>
<html>
<head>
    <title>CTF Challenge</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
        }
        .error {
            color: red;
            margin-bottom: 10px;
        }
        .success {
            color: green;
            margin-bottom: 10px;
        }
        input[type="text"], input[type="password"], input[type="file"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #ddd;
        }
        .user-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .user-table th, .user-table td {
            padding: 8px;
            border: 1px solid #ddd;
            text-align: left;
        }
        .user-table th {
            background-color: #f2f2f2;
        }
    </style>
</head>
<body>
    <div class="container">
        {% block content %}{% endblock %}
    </div>
</body>
</html>''')

    # Create login template
    with open('templates/login.html', 'w') as f:
        f.write('''
{% extends "base.html" %}
{% block content %}
    <h1>Login</h1>
    {% if error %}<p class="error">{{ error }}</p>{% endif %}
    <form method="post">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
    <p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a></p>
{% endblock %}
        ''')

    # Create register template
    with open('templates/register.html', 'w') as f:
        f.write('''
{% extends "base.html" %}
{% block content %}
    <h1>Register</h1>
    {% if error %}<p class="error">{{ error }}</p>{% endif %}
    <form method="post">
        <input type="text" name="username" placeholder="Username" required minlength="3">
        <input type="password" name="password" placeholder="Password" required minlength="4">
        <button type="submit">Register</button>
    </form>
    <p>Already have an account? <a href="{{ url_for('login') }}">Login here</a></p>
{% endblock %}
        ''')

    # Create index template
    with open('templates/index.html', 'w') as f:
        f.write('''
{% extends "base.html" %}
{% block content %}
    <h1>Welcome, {{ username }}!</h1>
    <p>Your role: {{ role }}</p>
    <img src="{{ get_uploads_path(profile_pic) }}" alt="Profile Picture" style="max-width: 200px; max-height: 200px;">
    <p>
        <a href="{{ url_for('profile') }}">Update Profile</a> |
        {% if role == 'admin' %}<a href="{{ url_for('admin_panel') }}">Admin Panel</a> | {% endif %}
        <a href="{{ url_for('search_users') }}">Search Users</a> |
        <a href="{{ url_for('logout') }}">Logout</a>
    </p>
{% endblock %}
        ''')

    # Create profile template
    with open('templates/profile.html', 'w') as f:
        f.write('''
{% extends "base.html" %}
{% block content %}
    <h1>Update Profile</h1>
    <img src="{{ get_uploads_path(profile_pic) }}" alt="Profile Picture" style="max-width: 200px; max-height: 200px;">
    {% if error %}<p class="error">{{ error }}</p>{% endif %}
    <h2>Upload Image File</h2>
    <form method="post" action="{{ url_for('update_profile_pic') }}" enctype="multipart/form-data">
        <input type="file" name="file" accept="image/*">
        <button type="submit">Upload</button>
    </form>
    <h2>OR Enter Image URL</h2>
    <form method="post" action="{{ url_for('update_profile_pic') }}">
        <input type="text" name="image_url" placeholder="https://example.com/image.jpg">
        <button type="submit">Use URL</button>
    </form>
    <p><a href="{{ url_for('index') }}">Back to Home</a></p>
{% endblock %}
        ''')

    # Create admin template
    with open('templates/admin.html', 'w') as f:
        f.write('''
{% extends "base.html" %}
{% block content %}
    <h1>Admin Panel</h1>
    
    <h2>User Management</h2>
    <table class="user-table">
        <thead>
            <tr>
                <th>Username</th>
                <th>Role</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            {% for user in users %}
            <tr>
                <td>{{ user.username }}</td>
                <td>{{ user.role }}</td>
                <td><a href="{{ url_for('manage_user', user_id=user.id) }}">Manage</a></td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    
    <h2>Uploaded Files</h2>
    <ul>
        {% for file in files %}
        <li><a href="{{ url_for('view_file', file=file) }}">{{ file }}</a></li>
        {% endfor %}
    </ul>
    <p><a href="{{ url_for('index') }}">Back to Home</a></p>
{% endblock %}
        ''')
        
    # Create manage user template
    with open('templates/manage_user.html', 'w') as f:
        f.write('''
{% extends "base.html" %}
{% block content %}
    <h1>Manage User: {{ user.username }}</h1>
    {% if error %}<p class="error">{{ error }}</p>{% endif %}
    {% if success %}<p class="success">{{ success }}</p>{% endif %}
    
    <h2>Current Information</h2>
    <p><strong>Username:</strong> {{ user.username }}</p>
    <p><strong>Role:</strong> {{ user.role }}</p>
    <p><strong>Profile Picture:</strong> {{ user.profile_pic }}</p>
    <img src="{{ get_uploads_path(user.profile_pic) }}" alt="Profile Picture" style="max-width: 200px; max-height: 200px;">
    
    <h2>Update Role</h2>
    <form method="post">
        <input type="hidden" name="action" value="update_role">
        <select name="role">
            <option value="user" {% if user.role == 'user' %}selected{% endif %}>User</option>
            <option value="admin" {% if user.role == 'admin' %}selected{% endif %}>Admin</option>
        </select>
        <button type="submit">Update Role</button>
    </form>
    
    <h2>Reset Password</h2>
    <form method="post" onsubmit="return confirm('Are you sure you want to reset this user\'s password?');">
        <input type="hidden" name="action" value="reset_password">
        <button type="submit">Generate New Password</button>
    </form>
    
    <h2>Delete User</h2>
    <form method="post" onsubmit="return confirm('Are you sure you want to delete this user? This action cannot be undone.');">
        <input type="hidden" name="action" value="delete_user">
        <button type="submit" {% if user.username == 'admin' %}disabled{% endif %}>Delete User</button>
    </form>
    
    <p><a href="{{ url_for('admin_panel') }}">Back to Admin Panel</a></p>
{% endblock %}
        ''')
        
        
    with open('templates/search.html', 'w') as f:
        f.write('''
{% extends "base.html" %}
{% block content %}
    <h1>Search Users</h1>

    <form method="get" action="{{ url_for('search_users') }}">
        <input type="text" name="q" placeholder="Search username..." value="{{ query }}">
        <button type="submit">Search</button>
    </form>

    {% if query %}
        <p>Showing results for: '<strong>{{ query }}</strong>'</p>
    {% endif %}

    {% if users %}
        <table class="user-table">
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Role</th>
                </tr>
            </thead>
            <tbody>
                {% for user in users %}
                <tr>
                    <td>{{ user.username }}</td>
                    <td>{{ user.role }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    {% else %}
        <p>No users found matching your search.</p>
    {% endif %}

    <p><a href="{{ url_for('index') }}">Back to Home</a></p>
{% endblock %}
        ''')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port='80')
