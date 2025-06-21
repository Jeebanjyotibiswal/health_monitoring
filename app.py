from flask import Flask, render_template, request, jsonify, url_for, session, redirect
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from dotenv import load_dotenv
import sqlite3
import os
import secrets

# Load environment variables
load_dotenv()

app = Flask(__name__)

# =======================
# CONFIGURATION
# =======================
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# =======================
# DATABASE SETUP
# =======================
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

def create_admin():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", ('admin@gmail.com',))
    if not cursor.fetchone():
        cursor.execute("""
            INSERT INTO users (name, email, phone, password, is_admin)
            VALUES (?, ?, ?, ?, ?)
        """, ('Admin', 'admin@gmail.com', '9999999999', 'admin123', 1))
        conn.commit()
    conn.close()

init_db()
create_admin()

# =======================
# HELPER FUNCTIONS
# =======================
def is_admin(email):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    return user and user[0] == 1

# =======================
# ROUTES
# =======================

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    name = request.form.get('name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    password = request.form.get('password')

    if not name or not email or not phone or not password:
        return jsonify({"status": "error", "message": "All fields are required."})

    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)",
                       (name, email, phone, password))
        conn.commit()
        return jsonify({"status": "success", "message": "Account created successfully."})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Email already registered."})
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    email_or_phone = request.form.get('email_or_phone')
    password = request.form.get('password')

    if not email_or_phone or not password:
        return jsonify({"status": "error", "message": "Please enter both credentials."})

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE (email=? OR phone=?) AND password=?",
                   (email_or_phone, email_or_phone, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        session['user_email'] = user[2]  # Save email in session
        session['username'] = user[1]   # Save name in session
        session['is_admin'] = bool(user[5])  # Save admin status
        return jsonify({
            "status": "success", 
            "username": user[1],
            "is_admin": bool(user[5])
        })
    else:
        return jsonify({"status": "error", "message": "Invalid credentials."})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/send-reset', methods=['POST'])
def send_reset():
    email = request.form.get('email')
    if not email:
        return jsonify({"status": "error", "message": "Email is required."})

    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            return jsonify({"status": "error", "message": "Email not found."})

        token = serializer.dumps(email, salt='reset-salt')
        reset_url = url_for('reset_password_form', token=token, _external=True)

        msg = Message("Password Reset Request", recipients=[email])
        msg.body = f"""Click this link to reset your password:
{reset_url}

This link will expire in 1 hour."""

        mail.send(msg)
        return jsonify({"status": "success", "message": "Reset link sent to your email."})

    except Exception as e:
        app.logger.error(f"Mail sending failed: {e}")
        return jsonify({"status": "error", "message": f"Mail sending failed. Error: {str(e)}"})

@app.route('/reset-password/<token>', methods=['GET'])
def reset_password_form(token):
    try:
        email = serializer.loads(token, salt='reset-salt', max_age=3600)
        return render_template('reset_form.html', token=token)
    except SignatureExpired:
        return render_template('error.html', message="This password reset link has expired.")
    except BadSignature:
        return render_template('error.html', message="Invalid reset link.")
    except Exception as e:
        return render_template('error.html', message="Unexpected error: " + str(e))

@app.route('/reset-password', methods=['POST'])
def reset_password():
    token = request.form.get('token')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not token or not new_password or not confirm_password:
        return jsonify({"status": "error", "message": "All fields are required."})

    if new_password != confirm_password:
        return jsonify({"status": "error", "message": "Passwords do not match."})

    try:
        email = serializer.loads(token, salt='reset-salt', max_age=3600)
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password=? WHERE email=?", (new_password, email))
        conn.commit()
        return jsonify({"status": "success", "message": "Password updated successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Error resetting password: {str(e)}"})
    finally:
        conn.close()

@app.route('/visualization.html')
def visualization():
    return render_template('visualization.html')

@app.route('/admin')
def admin_dashboard():
    if 'user_email' not in session:
        return redirect(url_for('home'))
    
    if not session.get('is_admin'):
        return "Access Denied", 403

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email, phone FROM users WHERE is_admin = 0")
    users = cursor.fetchall()
    conn.close()
    return render_template('admin.html', users=users)

# =======================
# MAIN
# =======================
if __name__ == '__main__':
    app.run(debug=True)