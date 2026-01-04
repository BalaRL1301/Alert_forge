import socket
import logging
import sqlite3
import hashlib
from flask import Flask, request, render_template_string, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_testing'

# Configuration
UDP_IP = "127.0.0.1"
UDP_PORT = 5140

def send_syslog(message, level="INFO"):
    """Send log directly to Collector via UDP"""
    try:
        # Format: TIMESTAMP - APP - LEVEL - MSG
        # Real syslog is more complex but our collector parses this format:
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
        log_msg = f"{timestamp} - VulnerableApp - {level} - {message}"
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(log_msg.encode(), (UDP_IP, UDP_PORT))
    except Exception as e:
        print(f"Failed to send syslog: {e}")

# We'll use this instead of logger
# logger = logging.getLogger('VulnerableApp') ... REMOVED

# Database Setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    # Add a default admin user
    try:
        # Check if admin exists
        c.execute("SELECT * FROM users WHERE username='admin'")
        if not c.fetchone():
            # Hash password for 'admin123'
            pwd_hash = hashlib.sha256('admin123'.encode()).hexdigest()
            c.execute("INSERT INTO users (username, password) VALUES ('admin', ?)", (pwd_hash,))
            conn.commit()
    except Exception as e:
        print(e)
    conn.close()

init_db()

# Login Page HTML
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Login</title>
    <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; }
        .login-box { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        input { display: block; margin: 10px 0; padding: 8px; width: 100%; box-sizing: border-box; }
        button { background: #0070f3; color: white; border: none; padding: 10px; width: 100%; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0051a2; }
        .error { color: red; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Login</h2>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Log the attempt
        send_syslog(f"Login attempt for user: {username} from IP: {request.remote_addr}")

        # VULNERABILITY: SQL Injection
        # The code directly concatenates the username into the query string.
        # Password is checked separately to allow "bypass authentication" scenarios if the query returns a user.
        # But a classic ' OR '1'='1 can bypass the username check.
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Intentional SQL Injection Vulnerability
        query = f"SELECT * FROM users WHERE username = '{username}'"
        try:
            print(f"Executing query: {query}") # Debug print
            c.execute(query)
            user = c.fetchone()
            
            if user:
                # In a real SQLi bypass, we might not even need the password if we log them in as the first user found.
                # However, for this demo, let's say if they inject successfully to return a user, we check password hash 
                # OR if they commented out the rest of the query.
                
                # Standard check
                pwd_hash = hashlib.sha256(password.encode()).hexdigest()
                
                # If SQLi was used to bypass username check, 'user' is the first record (admin).
                # We will check if the password matches OR if the username input contains SQLi chars that suggest an attack 
                # (though the goal is to let it succeed if it's a valid SQLi, but we want to LOG it for our detection engine).
                
                if user[2] == pwd_hash:
                     session['user'] = user[1]
                     send_syslog(f"Successful login for user: {username}")
                     return redirect(url_for('dashboard'))
                else:
                     send_syslog(f"Failed login (password mismatch) for user: {username}", "WARNING")
                     error = "Invalid credentials"
            else:
                send_syslog(f"Failed login (user not found) for user: {username}", "WARNING")
                error = "Invalid credentials"
                
        except Exception as e:
            send_syslog(f"SQL Error: {str(e)} - Query: {query}", "ERROR")
            error = f"Database Error: {e}"
        finally:
            conn.close()

    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return f"<h1>Welcome, {session['user']}!</h1><p>This is the secure area.</p><a href='/logout'>Logout</a>"

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Run on port 5001 to avoid conflict with Control Center or other things
    app.run(host='0.0.0.0', port=5001, debug=True)
