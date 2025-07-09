from flask import Flask, render_template, request, redirect, session
from pymongo import MongoClient
import bcrypt
from bson.objectid import ObjectId
from functools import wraps
from flask_dance.contrib.google import make_google_blueprint, google
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# MongoDB Setup
client = MongoClient("mongodb://localhost:27017/")
db = client['voting_db']
users = db['users']
votes = db['votes']
candidates = db['candidates']

# Encryption key for votes
FERNET_KEY = "1pfIeGLEeOJpsk5CRLOaodovMwe5-vbpfgDmC6Osiw8="
fernet = Fernet(FERNET_KEY.encode())

# Google OAuth Setup (replace with real credentials if using)
google_bp = make_google_blueprint(
    client_id="YOUR_GOOGLE_CLIENT_ID",
    client_secret="YOUR_GOOGLE_CLIENT_SECRET",
    redirect_to="google_login"
)
app.register_blueprint(google_bp, url_prefix="/login")

# -----------------------------
# Create predefined users
# -----------------------------
def create_admin():
    if not users.find_one({"email": "admin@voting.com"}):
        hashed = bcrypt.hashpw(b"admin123", bcrypt.gensalt())
        users.insert_one({
            "email": "admin@voting.com",
            "password": hashed,
            "voted": False
        })

def create_students():
    predefined_students = [
        {"email": "student1@gitam.in", "password": bcrypt.hashpw(b"pass123", bcrypt.gensalt()), "voted": False},
        {"email": "student2@gitam.in", "password": bcrypt.hashpw(b"pass456", bcrypt.gensalt()), "voted": False},
        {"email": "student3@gitam.in", "password": bcrypt.hashpw(b"pass789", bcrypt.gensalt()), "voted": False}
    ]
    for student in predefined_students:
        if not users.find_one({"email": student["email"]}):
            users.insert_one(student)

# Create admin and students at app startup
create_admin()
create_students()

# -----------------------------
# Admin route protection
# -----------------------------
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get('email') != 'admin@voting.com':
            return "Access Denied"
        return f(*args, **kwargs)
    return wrapper

# -----------------------------
# Routes
# -----------------------------

@app.route('/')
def home():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Student login
        student_email = request.form.get('studentEmail')
        student_password = request.form.get('studentPassword')
        admin_username = request.form.get('adminUsername')
        admin_password = request.form.get('adminPassword')

        if student_email and student_password:
            user = users.find_one({"email": student_email})
            if user and bcrypt.checkpw(student_password.encode(), user['password']):
                session['email'] = student_email
                return redirect('/vote')
            return "Invalid Student Credentials", 401

        elif admin_username and admin_password:
            admin = users.find_one({"email": admin_username})
            if admin and bcrypt.checkpw(admin_password.encode(), admin['password']):
                session['email'] = admin_username
                return redirect('/admin')
            return "Invalid Admin Credentials", 401

        return "Missing credentials", 400

    return render_template('login.html')

@app.route('/google_login')
def google_login():
    if not google.authorized:
        return redirect('/login')
    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return "Google login failed"

    email = resp.json()["email"]
    user = users.find_one({"email": email})
    if not user:
        return "Access denied. Not a registered student."
    session['email'] = email
    return redirect('/admin' if email == "admin@voting.com" else '/vote')

@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if 'email' not in session:
        return redirect('/login')

    user = users.find_one({"email": session['email']})
    if user.get('voted'):
        return "You have already voted."

    all_candidates = [c['name'] for c in candidates.find()]

    if request.method == 'POST':
        selected = request.form.get('candidate')
        if not selected:
            return "Please select a candidate.", 400

        encrypted_vote = fernet.encrypt(selected.encode())
        votes.insert_one({"email": session['email'], "vote": encrypted_vote})
        users.update_one({"email": session['email']}, {"$set": {"voted": True}})
        return redirect('/result')

    return render_template('vote.html', candidates=all_candidates)

@app.route('/result')
def result():
    if 'email' not in session:
        return redirect('/login')

    if session['email'] != 'admin@voting.com':
        return render_template('thanks.html')

    results = {c['name']: 0 for c in candidates.find()}
    for v in votes.find():
        try:
            decrypted = fernet.decrypt(v['vote']).decode()
            if decrypted in results:
                results[decrypted] += 1
        except:
            continue

    return render_template('result.html', results=results)

@app.route('/admin')
@admin_required
def admin():
    all_candidates = list(candidates.find())
    vote_counts = {c['name']: 0 for c in all_candidates}

    for v in votes.find():
        try:
            decrypted = fernet.decrypt(v['vote']).decode()
            if decrypted in vote_counts:
                vote_counts[decrypted] += 1
        except:
            continue

    for c in all_candidates:
        c['votes'] = vote_counts[c['name']]

    total_votes = sum(c['votes'] for c in all_candidates)

    return render_template('admin.html', candidates=all_candidates, total_votes=total_votes)

@app.route('/admin/add', methods=['POST'])
@admin_required
def add_candidate():
    name = request.form.get('name')
    if not name:
        return "Candidate name is required.", 400
    candidates.insert_one({"name": name})
    return redirect('/admin')

@app.route('/admin/delete/<id>')
@admin_required
def delete_candidate(id):
    candidates.delete_one({"_id": ObjectId(id)})
    return redirect('/admin')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# -----------------------------
# Run
# -----------------------------
if __name__ == '__main__':
    app.run(debug=True)
