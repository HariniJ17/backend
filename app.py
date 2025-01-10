from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from flask_cors import CORS

app = Flask(__name__)

# Allow CORS for the frontend's specific URL (Make sure to adjust this URL if needed)
CORS(app, resources={r"/signup": {"origins": "https://harinij17.github.io"}})

# Database initialization
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        email TEXT NOT NULL,
                        password TEXT NOT NULL)''')
    conn.commit()
    conn.close()

# Signup route
@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']

    # Hash the password before storing it
    hashed_password = generate_password_hash(password)

    # Connect to SQLite database and insert the user data
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, hashed_password))
    conn.commit()
    conn.close()

    return jsonify({"message": "Signup successful"}), 201

# Login route
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # Connect to SQLite database and fetch the user data by username
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[3], password):  # user[3] is the hashed password column
        # If the user exists and the password matches
        return jsonify({"message": f"Welcome, {username}"}), 200
    else:
        # If username or password is incorrect
        return jsonify({"message": "Invalid credentials"}), 401

if __name__ == '__main__':
    init_db()  # Initialize the database
    app.run(debug=True)
