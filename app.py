import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'supersecretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_web'

class User(UserMixin):
    def __init__(self, id, email, password):
        self.id = id
        self.email = email
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user_data = cursor.fetchone()
        if user_data:
            return User(id=user_data[0], email=user_data[1], password=user_data[2])
        return None

def init_db():
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()

@app.after_request
def add_header(response):
    """
    Add headers to ensure responses are not cached.
    """
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    return response

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register_web():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validate passwords
        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match")

        if not email or not password:
            return render_template('register.html', error="All fields are required")

        hashed_password = generate_password_hash(password)

        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()

            # Check if email already exists
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            if cursor.fetchone():
                return render_template('register.html', error="Email already exists")

            # Check if password is already in use
            cursor.execute('SELECT password FROM users')
            existing_passwords = cursor.fetchall()

            for existing_password in existing_passwords:
                if check_password_hash(existing_password[0], password):
                    return render_template(
                        'register.html',
                        error="This password is already in use. Please choose a unique password."
                    )

            # Insert the new user
            cursor.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
            conn.commit()

        flash("Registration successful! Please log in.")
        return redirect(url_for('login_web'))
    
    # Clear previous success or error messages
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login_web():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            return render_template('login.html', error="Email and password are required")

        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            user_data = cursor.fetchone()

        if user_data and check_password_hash(user_data[2], password):
            user = User(id=user_data[0], email=user_data[1], password=user_data[2])
            login_user(user)
            return redirect(url_for('dashboard'))

        return render_template('login.html', error="Invalid email or password")
    
    # Clear previous success or error messages
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user.email)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login_web'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not email or not new_password or not confirm_password:
            return render_template('forgot_password.html', error="All fields are required")

        if new_password != confirm_password:
            return render_template('forgot_password.html', error="Passwords do not match")

        if len(new_password) < 6:
            return render_template('forgot_password.html', error="Password must be at least 6 characters long")

        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            # Check if email exists in the database
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            user_data = cursor.fetchone()

            if not user_data:
                return render_template('forgot_password.html', error="Email does not exist. Consider creating an account.")

            # Check if the new password already exists in the database
            cursor.execute('SELECT password FROM users')
            existing_passwords = cursor.fetchall()

            for existing_password in existing_passwords:
                if check_password_hash(existing_password[0], new_password):
                    return render_template(
                        'forgot_password.html',
                        error="This password is already in use. Please choose a unique password."
                    )

            # Update the user's password
            hashed_password = generate_password_hash(new_password)
            cursor.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_password, email))
            conn.commit()

        flash("Password reset successfully! Please log in.", "success")
        return redirect(url_for('login_web'))

    return render_template('forgot_password.html')


if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
