from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)

# A new vulnerable service: "CTF Challenge Blog"
# Vulnerabilities:
# 1. SQL Injection in 'search' parameter
# 2. RCE in 'ping' feature
# 3. XSS in 'comment' preview

def init_db():
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY, title TEXT, content TEXT)''')
    c.execute("INSERT OR IGNORE INTO posts (title, content) VALUES ('Welcome', 'Welcome to the CTF Blog')")
    c.execute("INSERT OR IGNORE INTO posts (title, content) VALUES ('Secret', 'The flag is CTF{Y0u_F0und_M3}')")
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return '''
    <h1>Super Secure Blog</h1>
    <a href="/search?q=Welcome">Search Posts</a> | 
    <a href="/ping?target=127.0.0.1">Ping Status</a> |
    <a href="/comment">Leave a Comment</a>
    '''

@app.route('/search')
def search():
    query = request.args.get('q', '')
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    
    # VULN: SQL Injection
    # "SELECT * FROM posts WHERE title LIKE '%" + query + "%'"
    sql = f"SELECT * FROM posts WHERE title LIKE '%{query}%'"
    
    try:
        c.execute(sql)
        results = c.fetchall()
    except Exception as e:
        return f"Database Error: {e}"
    
    return f"<h2>Search Results for '{query}'</h2><pre>{results}</pre>"

@app.route('/ping')
def ping():
    target = request.args.get('target', '127.0.0.1')
    # VULN: Command Injection (RCE)
    cmd = f"ping -c 1 {target}"
    stream = os.popen(cmd)
    output = stream.read()
    return f"<pre>{output}</pre>"

@app.route('/comment')
def comment():
    msg = request.args.get('msg', '')
    if msg:
        # VULN: SSTI / XSS
        # Using render_template_string on user input
        template = f"Your comment: <b>{msg}</b>"
        return render_template_string(template)
    
    return '''
    <form>
        Comment: <input name="msg"> <input type="submit">
    </form>
    '''

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)
