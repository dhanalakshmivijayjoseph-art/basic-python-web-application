"""Small local authentication API for the Figma login demo.

Run with: python backend.py
The API listens on http://127.0.0.1:5000 and stores accounts in auth.db.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HOST = "127.0.0.1"
PORT = 5000
DB_PATH = Path(__file__).with_name("auth.db")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PBKDF2_ROUNDS = 310_000
TOKEN_LIFETIME = 60 * 60 * 24 * 7


def connect_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with connect_db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL, password_hash TEXT NOT NULL,
            salt TEXT NOT NULL, created_at INTEGER NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)""")
        demo_email = "demo@example.com"
        if db.execute("SELECT 1 FROM users WHERE email=?", (demo_email,)).fetchone() is None:
            salt, password_hash = hash_password("Demo123!")
            db.execute("INSERT INTO users(email,name,password_hash,salt,created_at) VALUES (?,?,?,?,?)",
                       (demo_email, "Demo User", password_hash, salt, int(time.time())))


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return salt.hex(), digest.hex()


def make_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with connect_db() as db:
        db.execute("DELETE FROM sessions WHERE expires_at < ?", (int(time.time()),))
        db.execute("INSERT INTO sessions VALUES (?, ?, ?)",
                   (token_hash, user_id, int(time.time()) + TOKEN_LIFETIME))
    return token


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "LocalAuthAPI/1.0"

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def send_json(self, status: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", self.allowed_origin())
        self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def allowed_origin(self):
        origin = self.headers.get("Origin", "")
        if origin.startswith(("http://localhost:8000", "http://127.0.0.1:8000",
                              "http://localhost:8080", "http://127.0.0.1:8080")):
            return origin
        return "http://localhost:8000"

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", self.allowed_origin())
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Max-Age", "600")
        self.end_headers()

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 16_384:
                return None
            data = json.loads(self.rfile.read(length) or b"{}")
            return data if isinstance(data, dict) else None
        except (ValueError, json.JSONDecodeError):
            return None

    def get_session_user(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        token_hash = hashlib.sha256(header[7:].encode()).hexdigest()
        with connect_db() as db:
            return db.execute("""SELECT users.id, users.email, users.name
                FROM sessions JOIN users ON users.id=sessions.user_id
                WHERE sessions.token_hash=? AND sessions.expires_at>?""",
                (token_hash, int(time.time()))).fetchone()

    def do_GET(self):
        route = urlparse(self.path).path
        if route == "/api/health":
            return self.send_json(200, {"success": True, "service": "auth-api"})
        if route == "/api/me":
            user = self.get_session_user()
            if user is None:
                return self.send_json(401, {"success": False, "message": "Please sign in."})
            return self.send_json(200, {"success": True, "user": {"email": user["email"], "name": user["name"]}})
        self.send_json(404, {"success": False, "message": "Endpoint not found."})

    def do_POST(self):
        route = urlparse(self.path).path
        if route == "/api/logout":
            header = self.headers.get("Authorization", "")
            if header.startswith("Bearer "):
                digest = hashlib.sha256(header[7:].encode()).hexdigest()
                with connect_db() as db:
                    db.execute("DELETE FROM sessions WHERE token_hash=?", (digest,))
            return self.send_json(200, {"success": True, "message": "Signed out."})

        data = self.read_json()
        if data is None:
            return self.send_json(400, {"success": False, "message": "Send a valid JSON request."})
        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", ""))
        if not EMAIL_RE.fullmatch(email):
            return self.send_json(400, {"success": False, "message": "Enter a valid email address."})
        if len(password) < 6 or len(password) > 128:
            return self.send_json(400, {"success": False, "message": "Password must be 6 to 128 characters."})

        if route == "/api/register":
            name = str(data.get("name", "")).strip()
            if len(name) < 2 or len(name) > 80:
                return self.send_json(400, {"success": False, "message": "Enter your name (2–80 characters)."})
            salt, password_hash = hash_password(password)
            try:
                with connect_db() as db:
                    cursor = db.execute("INSERT INTO users(email,name,password_hash,salt,created_at) VALUES (?,?,?,?,?)",
                                        (email, name, password_hash, salt, int(time.time())))
                    user_id = cursor.lastrowid
            except sqlite3.IntegrityError:
                return self.send_json(409, {"success": False, "message": "An account with that email already exists."})
            token = make_session(user_id)
            return self.send_json(201, {"success": True, "message": "Your account is ready.", "token": token,
                                        "user": {"email": email, "name": name}})

        if route == "/api/login":
            with connect_db() as db:
                user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if user is None:
                return self.send_json(401, {"success": False, "message": "Email or password is incorrect."})
            salt, expected = bytes.fromhex(user["salt"]), user["password_hash"]
            _, actual = hash_password(password, salt)
            if not hmac.compare_digest(actual, expected):
                return self.send_json(401, {"success": False, "message": "Email or password is incorrect."})
            token = make_session(user["id"])
            return self.send_json(200, {"success": True, "message": "Signed in successfully.", "token": token,
                                        "user": {"email": user["email"], "name": user["name"]}})

        self.send_json(404, {"success": False, "message": "Endpoint not found."})


if __name__ == "__main__":
    init_db()
    print(f"Auth API listening at http://localhost:{PORT}")
    print(f"SQLite database: {DB_PATH}")
    ThreadingHTTPServer((HOST, PORT), ApiHandler).serve_forever()
