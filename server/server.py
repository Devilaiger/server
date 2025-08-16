import os
import sqlite3
import datetime
import secrets
from functools import wraps
from flask import (
    Flask, request, jsonify, render_template, redirect,
    url_for, session, abort
)

# --------------------
# CONFIG
# --------------------
DB_FILE = "keys.db"

# Admin panel creds (ONLY you know these)
# FOR TESTING - Change these to your own secure credentials!
ADMIN_USERNAME = os.environ.get("FF_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("FF_ADMIN_PASS", "admin123")

# API key for clients (rotate periodically; distribute only with obfuscated client)
API_KEY = os.environ.get("FF_API_KEY", "my_secret_api_key_12345")

# Optional: restrict who can see admin (simple IP allowlist)
ADMIN_ALLOWED_IPS = os.environ.get("FF_ADMIN_IPS", "")  # e.g. "1.2.3.4,5.6.7.8"
ADMIN_ALLOWED_IPS = [ip.strip() for ip in ADMIN_ALLOWED_IPS.split(",") if ip.strip()]

# For development - disable HTTPS
USE_HTTPS = os.environ.get("FF_USE_HTTPS", "false").lower() == "true"
CERT_FILE = os.environ.get("FF_CERT_FILE", "certs/cert.pem")
KEY_FILE  = os.environ.get("FF_KEY_FILE",  "certs/key.pem")

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # session protection

print("🔥 FF Bot Server Starting...")
print(f"👤 Admin Username: {ADMIN_USERNAME}")
print(f"🔑 Admin Password: {ADMIN_PASSWORD}")
print(f"🗝️ API Key: {API_KEY}")
print(f"🔒 HTTPS Enabled: {USE_HTTPS}")

# --------------------
# DB INIT
# --------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            expiry DATE NOT NULL
        )
    """)
    
    # Add some sample data for testing
    sample_data = [
        ("demo", "1234", "2025-12-31"),
        ("testuser", "password", "2025-09-01"),
        ("premium_user", "secure123", "2025-06-15"),
        ("vip_member", "vip2024", "2025-08-20"),
        ("expired_user", "old123", "2024-01-01"),
    ]
    
    for user_id, password, expiry in sample_data:
        c.execute("INSERT OR IGNORE INTO keys (id, password, expiry) VALUES (?, ?, ?)",
                  (user_id, password, expiry))
    
    conn.commit()
    conn.close()
    print("✅ Database initialized with sample keys")

def get_db():
    return sqlite3.connect(DB_FILE)

init_db()

# --------------------
# HELPERS & GUARDS
# --------------------
def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        # Optional IP allowlist for admin routes
        if ADMIN_ALLOWED_IPS:
            client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
            if client_ip not in ADMIN_ALLOWED_IPS:
                return "Not allowed from this IP", 403

        if session.get("admin") is True:
            return view(*args, **kwargs)
        return redirect(url_for("admin_login"))
    return wrapper

def require_api_key(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        # Only API routes use API key
        provided = request.headers.get("X-API-Key")
        if not provided or provided != API_KEY:
            return jsonify({"status": "forbidden", "error": "Invalid API key"}), 403
        return view(*args, **kwargs)
    return wrapper

# --------------------
# ADMIN ROUTES
# --------------------
@app.route("/", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        print(f"🔐 Login attempt: {u} / {'*' * len(p)}")
        if u == ADMIN_USERNAME and p == ADMIN_PASSWORD:
            session["admin"] = True
            print("✅ Admin login successful")
            return redirect(url_for("dashboard"))
        print("❌ Invalid admin credentials")
        return "Invalid login", 403
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/dashboard")
@admin_required
def dashboard():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, password, expiry FROM keys ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()
    print(f"📊 Dashboard accessed - {len(rows)} keys in database")
    return render_template("dashboard.html", keys=rows)

@app.route("/add_key", methods=["POST"])
@admin_required
def add_key():
    user_id = request.form.get("id", "").strip()
    password = request.form.get("password", "").strip()
    days = int(request.form.get("days", "0"))

    if not user_id or not password or days <= 0:
        return "Invalid input", 400

    expiry = (datetime.date.today() + datetime.timedelta(days=days)).strftime("%Y-%m-%d")
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO keys (id, password, expiry) VALUES (?, ?, ?)",
              (user_id, password, expiry))
    conn.commit()
    conn.close()
    print(f"🔑 Key added/updated: {user_id} expires {expiry}")
    return redirect(url_for("dashboard"))

@app.route("/delete_key/<user_id>", methods=["POST"])
@admin_required
def delete_key(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM keys WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    print(f"🗑️ Key deleted: {user_id}")
    return redirect(url_for("dashboard"))

@app.route("/reactivate_key", methods=["POST"])
@admin_required
def reactivate_key():
    """Reactivate an expired key with new expiry date"""
    user_id = request.form.get("user_id", "").strip()
    days = int(request.form.get("days", "0"))

    if not user_id or days <= 0:
        return jsonify({"status": "error", "message": "Invalid input"}), 400

    # Check if user exists
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, expiry FROM keys WHERE id = ?", (user_id,))
    row = c.fetchone()
    
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "User not found"}), 404

    # Calculate new expiry date
    new_expiry = (datetime.date.today() + datetime.timedelta(days=days)).strftime("%Y-%m-%d")
    
    # Update the key with new expiry
    c.execute("UPDATE keys SET expiry = ? WHERE id = ?", (new_expiry, user_id))
    conn.commit()
    conn.close()
    
    print(f"🔄 Key reactivated: {user_id} expires {new_expiry}")
    return jsonify({
        "status": "success", 
        "message": f"User {user_id} reactivated for {days} days",
        "new_expiry": new_expiry
    })

# --------------------
# API ROUTES (FOR CLIENT VERIFICATION)
# --------------------
@app.route("/api/verify", methods=["POST"])
@require_api_key
def api_verify():
    data = request.get_json(force=True, silent=True) or {}
    user_id = data.get("id", "")
    password = data.get("password", "")
    
    print(f"🔍 API verification request: {user_id}")

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT expiry FROM keys WHERE id=? AND password=?", (user_id, password))
    row = c.fetchone()
    conn.close()

    if not row:
        print(f"❌ Invalid credentials for: {user_id}")
        return jsonify({"status": "invalid"}), 200

    expiry = datetime.datetime.strptime(row[0], "%Y-%m-%d").date()
    today = datetime.date.today()
    
    # IMPORTANT: Block expired keys from verification - they cannot access the system
    if today > expiry:
        print(f"🚫 Expired key BLOCKED: {user_id} (expired on {expiry})")
        return jsonify({"status": "expired", "message": "Key has expired and is inactive"}), 200
    
    # Key is active and valid
    days_left = (expiry - today).days
    print(f"✅ Valid key: {user_id}, {days_left} days left")
    return jsonify({"status": "ok", "days_left": days_left, "expiry": row[0]}), 200

# --------------------
# DASHBOARD API ENDPOINTS
# --------------------
@app.route("/api/dashboard/stats")
@admin_required
def dashboard_stats():
    """Get dashboard statistics"""
    conn = get_db()
    c = conn.cursor()
    
    # Total users
    c.execute("SELECT COUNT(*) FROM keys")
    total_users = c.fetchone()[0]
    
    # Active users (not expired)
    today = datetime.date.today().strftime("%Y-%m-%d")
    c.execute("SELECT COUNT(*) FROM keys WHERE expiry >= ?", (today,))
    active_users = c.fetchone()[0]
    
    # Expired users
    c.execute("SELECT COUNT(*) FROM keys WHERE expiry < ?", (today,))
    expired_users = c.fetchone()[0]
    
    # Users expiring in 7 days
    week_from_now = (datetime.date.today() + datetime.timedelta(days=7)).strftime("%Y-%m-%d")
    c.execute("SELECT COUNT(*) FROM keys WHERE expiry BETWEEN ? AND ?", (today, week_from_now))
    expiring_soon = c.fetchone()[0]
    
    # Recent activity (last 24 hours simulation)
    recent_activity = [
        {"user": "demo", "action": "Login", "time": "2 hours ago"},
        {"user": "testuser", "action": "Key verified", "time": "5 hours ago"},
        {"user": "admin", "action": "Dashboard access", "time": "1 hour ago"}
    ]
    
    conn.close()
    
    return jsonify({
        "total_users": total_users,
        "active_users": active_users,
        "expired_users": expired_users,
        "expiring_soon": expiring_soon,
        "recent_activity": recent_activity,
        "server_uptime": "24h 15m",
        "api_requests_today": 156,
        "success_rate": 98.7
    })

@app.route("/api/dashboard/users")
@admin_required
def dashboard_users():
    """Get all users with detailed info"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, password, expiry FROM keys ORDER BY expiry DESC")
    rows = c.fetchall()
    conn.close()
    
    users = []
    today = datetime.date.today()
    
    for row in rows:
        expiry = datetime.datetime.strptime(row[2], "%Y-%m-%d").date()
        days_left = (expiry - today).days
        status = "active" if days_left > 0 else "expired"
        if 0 < days_left <= 7:
            status = "expiring"
        
        users.append({
            "id": row[0],
            "password": row[1],
            "expiry": row[2],
            "days_left": days_left,
            "status": status
        })
    
    return jsonify({"users": users})

@app.route("/api/dashboard/analytics")
@admin_required
def dashboard_analytics():
    """Get analytics data for charts"""
    # Simulated data for demo - replace with real analytics
    return jsonify({
        "user_growth": {
            "labels": ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
            "data": [10, 25, 40, 35, 50, 65]
        },
        "login_activity": {
            "labels": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
            "data": [45, 52, 38, 65, 59, 80, 42]
        },
        "subscription_types": {
            "labels": ["Active", "Expired", "Expiring Soon"],
            "data": [65, 25, 10],
            "colors": ["#00ff88", "#ff4444", "#ffaa00"]
        },
        "api_usage": {
            "labels": ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00"],
            "data": [12, 8, 25, 45, 38, 22]
        }
    })

@app.route("/api/dashboard/notifications")
@admin_required
def dashboard_notifications():
    """Get system notifications"""
    return jsonify({
        "notifications": [
            {
                "id": 1,
                "type": "warning",
                "title": "Users Expiring Soon",
                "message": "3 users will expire in the next 7 days",
                "time": "5 minutes ago",
                "icon": "⚠️"
            },
            {
                "id": 2,
                "type": "success",
                "title": "Server Status",
                "message": "All systems operational",
                "time": "1 hour ago",
                "icon": "✅"
            },
            {
                "id": 3,
                "type": "info",
                "title": "New User Registration",
                "message": "User 'newuser123' registered successfully",
                "time": "3 hours ago",
                "icon": "👤"
            }
        ]
    })

# --------------------
# MAIN
# --------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n🌐 Server will run on port {port}")
    print(f"📱 Admin panel: http://localhost:{port}")
    print(f"👤 Login with: {ADMIN_USERNAME} / {ADMIN_PASSWORD}")
    print("\n" + "="*50)

    app.run(host="0.0.0.0", port=port, debug=True)
