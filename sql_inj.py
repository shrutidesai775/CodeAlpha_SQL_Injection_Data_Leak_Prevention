from flask import Flask, request
import sqlite3
from cryptography.fernet import Fernet
import secrets

app = Flask(__name__)

# Load AES encryption key
with open("secret.key", "rb") as key_file:
    key = key_file.read()

cipher = Fernet(key)

# Capability code for protected database access
CAPABILITY_CODE = secrets.token_hex(16)


def get_db():
    return sqlite3.connect("users.db")


@app.route("/")
def home():
    return """
    <h1>CodeAlpha Task 2</h1>
    <h2>SQL Injection Data Leak Prevention</h2>

    <form action="/register" method="post">
        <input name="username" placeholder="Username" required><br><br>
        <input name="password" type="password" placeholder="Password" required><br><br>
        <button type="submit">Register</button>
    </form>
    """


@app.route("/register", methods=["POST"])
def register():

    username = request.form["username"]
    password = request.form["password"]

    # Layer 1: Input validation
    if len(username) < 3 or len(password) < 6:
        return "Invalid input. Username must be 3+ characters and password 6+ characters."

    # Layer 2: AES encryption
    encrypted_password = cipher.encrypt(password.encode())

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Parameterized query prevents SQL Injection
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, encrypted_password.decode())
        )

        conn.commit()

    except sqlite3.IntegrityError:
        conn.close()
        return "Username already exists."

    conn.close()

    return "User registered securely!"


@app.route("/secure")
def secure_access():

    code = request.args.get("code")

    if code != CAPABILITY_CODE:
        return "Access denied!"

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id, username FROM users")
    users = cursor.fetchall()

    conn.close()

    return str(users)


if __name__ == "__main__":
    print("Capability Code:", CAPABILITY_CODE)
    app.run(debug=True)