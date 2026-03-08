from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

# EDUCATIONAL PURPOSE ONLY: This application contains intentional vulnerabilities
# for testing security tools (e.g., regex filters, WAFs).
# DO NOT deploy this in a production environment.

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'secret_admin_pass')")
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('user', 'user_pass')")
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return '''
    <h1>Vulnerable Test Service</h1>
    <ul>
        <li><a href="/login">SQL Injection Login</a></li>
        <li><a href="/search?q=test">Reflected XSS Search</a></li>
    </ul>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        try:
            c.execute(query)
            user = c.fetchone()
        except Exception as e:
            return f"Database error: {e}"
        finally:
            conn.close()

        if user:
            return f"Welcome, {user[1]}! (Logged in via SQLi)"
        else:
            return "Invalid credentials"
            
    return '''
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="text" name="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    template = f'''
    <h2>Search Results</h2>
    <p>You searched for: {query}</p>
    '''
    return render_template_string(template)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
