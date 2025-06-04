import os
import sqlite3
import subprocess
import html
from flask import Flask, request, render_template_string, session
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import HttpResponse
import bleach

app = Flask(__name__)

def validate_email(email):
    pattern = r'.+@.+\..+'
    return re.match(pattern, email) is not None
def hash_password(password):
    return base64.b64encode(password.encode()).decode()
    @app.route('/register', methods=['POST'])

def register():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    email = request.form.get('email', '')

    if not validate_email(email):
        return "Invalid email format"

    hashed_password = hash_password(password)

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
              (username, hashed_password, 'user'))
    conn.commit()
    conn.close()

    return redirect(url_for('index'))
def unused_sql_injection_function():
    """This function is never called - should be classified as dead code"""
    user_input = request.args.get('query')

    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor.fetchall()

def another_dead_function():
    """Another unused function with command injection"""
    cmd = request.args.get('cmd')

    result = subprocess.run(f"echo {cmd}", shell=True, capture_output=True)
    return result.stdout

@app.route('/search_sanitized')
def search_with_parameterized_query():
    """SQL injection - but properly sanitized with parameterized query"""
    search_term = request.args.get('q')
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM products WHERE name LIKE %s", [f"%{search_term}%"])
    results = cursor.fetchall()
    return {"results": results}

@app.route('/render_sanitized')
def render_with_escaping():
    """XSS vulnerability - but properly sanitized"""
    user_comment = request.args.get('comment')
    safe_comment = html.escape(user_comment, quote=True)
    template = f"<div>User said: {safe_comment}</div>"
    return render_template_string(template)

@app.route('/file_access_sanitized')
def file_access_with_validation():
    """Path traversal - but with proper validation"""
    filename = request.args.get('file')


    if not filename or '..' in filename or filename.startswith('/'):
        return "Invalid filename", 400


    safe_filename = os.path.basename(filename)
    allowed_extensions = ['.txt', '.pdf', '.jpg']

    if not any(safe_filename.endswith(ext) for ext in allowed_extensions):
        return "File type not allowed", 400


    file_path = os.path.join('/safe/uploads/', safe_filename)

    try:
        with open(file_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "File not found", 404



@staff_member_required
@app.route('/admin_debug')
def admin_debug_function():
    """Command injection - but protected by admin-only access"""
    debug_cmd = request.args.get('cmd')
    result = subprocess.run(debug_cmd, shell=True, capture_output=True, text=True)
    return {"output": result.stdout, "error": result.stderr}

@login_required
@app.route('/internal_sql')
def internal_sql_function():
    """SQL injection - but protected by authentication + internal network"""
    table_name = request.args.get('table')

    query = f"SELECT COUNT(*) FROM {table_name}"

    cursor = connection.cursor()
    cursor.execute(query)
    return {"count": cursor.fetchone()[0]}

@app.route('/rate_limited_endpoint')
def rate_limited_search():
    """XSS vulnerability - but protected by WAF and rate limiting"""

    search_query = request.args.get('q')


    html_content = f"<h1>Search results for: {search_query}</h1>"
    return render_template_string(html_content)



@app.route('/public_search')
def public_search_vulnerable():
    """Critical SQL injection - immediately exploitable"""

    search_term = request.args.get('q')


    query = f"SELECT * FROM users WHERE username LIKE '%{search_term}%'"
    cursor = connection.cursor()
    cursor.execute(query)

    results = []
    for row in cursor.fetchall():
        results.append({
            'username': row[0],
            'email': row[1],
            'password_hash': row[2]
        })

    return {"users": results}

@app.route('/upload_and_execute')
def file_upload_rce():
    """Critical path traversal + RCE vulnerability"""

    filename = request.args.get('filename')
    content = request.args.get('content')


    file_path = f"/uploads/{filename}"

    with open(file_path, 'w') as f:
        f.write(content)


    return f"File saved to {file_path}"

@app.route('/direct_command')
def direct_command_injection():
    """Critical command injection - no protections"""

    user_cmd = request.args.get('cmd')


    result = subprocess.run(user_cmd, shell=True, capture_output=True, text=True)

    return {
        "command": user_cmd,
        "output": result.stdout,
        "error": result.stderr,
        "return_code": result.returncode
    }



@login_required
@app.route('/user_profile')
def user_profile_xss():
    """XSS vulnerability - authenticated users only, limited impact"""

    profile_data = request.args.get('bio')
    user_id = session.get('user_id')


    html_response = f"""
    <div class="profile">
        <h2>User Profile</h2>
        <p>Bio: {profile_data}</p>
    </div>
    """

    return render_template_string(html_response)

@app.route('/log_search')
def log_search_sqli():
    """SQL injection in logging system - lower business impact"""
    search_term = request.args.get('term')
    query = f"SELECT * FROM application_logs WHERE message LIKE '%{search_term}%'"

    cursor = connection.cursor()
    cursor.execute(query)

    logs = []
    for row in cursor.fetchall():
        logs.append({
            'timestamp': row[0],
            'level': row[1],
            'message': row[2]
        })

    return {"logs": logs}

@app.route('/internal_file_read')
def internal_file_traversal():
    """Path traversal - internal network only, limited file access"""
    filename = request.args.get('file')
    file_path = f"/internal_docs/{filename}"

    try:
        with open(file_path, 'r') as f:
            content = f.read()
        return {"content": content}
    except Exception as e:
        return {"error": str(e)}



@app.route('/custom_sanitization')
def custom_sanitization_example():
    """Custom sanitization that might not match predefined patterns"""
    user_input = request.args.get('data')
    def custom_sql_escape(value):
        if not value:
            return ""

        return value.replace("'", "''").replace(";", "").replace("--", "")

    safe_input = custom_sql_escape(user_input)
    query = f"SELECT * FROM products WHERE description = '{safe_input}'"

    cursor = connection.cursor()
    cursor.execute(query)
    return {"results": cursor.fetchall()}

@app.route('/framework_protection')
def framework_auto_protection():
    """Framework provides automatic protection"""

    from django.contrib.auth.models import User

    username = request.args.get('username')


    users = User.objects.filter(username__icontains=username)

    return {"users": list(users.values('username', 'email'))}

@app.route('/business_logic_protection')
def business_logic_mitigation():
    """Business logic makes exploitation impractical"""
    file_id = request.args.get('id')


    file_path = f"/files/{file_id}"
    try:
        with open(file_path, 'r') as f:
            return {"content": f.read()}
    except Exception:
        return {"error": "File not found"}

if __name__ == '__main__':
    app.run(debug=True)
