from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
from flask_wtf.csrf import CSRFProtect
from functools import wraps
import sqlite3
import os
import csv
import io
import json
import shutil
import bcrypt
from datetime import datetime

# ---------------------- FLASK APP CONFIG ---------------------- #

app = Flask(__name__)
# Use persistent secret key (stored in environment or file)
SECRET_KEY_FILE = os.path.join(os.path.dirname(__file__), '.secret_key')
if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, 'r') as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(32).hex()
    with open(SECRET_KEY_FILE, 'w') as f:
        f.write(app.secret_key)

# CSRF Protection disabled temporarily for debugging
csrf = CSRFProtect(app)

# Disable CSRF protection globally
app.config['WTF_CSRF_ENABLED'] = False

# Database file path
DATABASE = os.path.join(os.path.dirname(__file__), 'student_health.db')
BACKUP_DIR = os.path.join(os.path.dirname(__file__), 'backups')

# Ensure backup directory exists
os.makedirs(BACKUP_DIR, exist_ok=True)

# ---------------------- USER ROLES ---------------------- #
ROLES = {
    'super_admin': 'Super Administrator',
    'health_officer': 'Health Officer',
    'class_advisor': 'Class Advisor',
    'teacher_view_only': 'Teacher (View Only)'
}

# ---------------------- CONTEXT PROCESSORS ---------------------- #

@app.before_request
def check_user_status():
    """Check if logged-in user's account is still active"""
    if session.get("logged_in"):
        # Allow access to login and logout routes
        if request.endpoint in ['login', 'logout', 'register']:
            return
        
        db = get_db_connection()
        if db:
            try:
                cursor = db.cursor()
                cursor.execute("SELECT is_active FROM users WHERE id = ?", (session.get("user_id"),))
                user = cursor.fetchone()
                db.close()
                
                if not user or not safe_row_get(user, 'is_active', 1):
                    # User account has been deactivated
                    session.clear()
                    flash("Your account has been disabled. Please contact the administrator.", "danger")
                    return redirect(url_for("login"))
            except sqlite3.Error:
                db.close()

@app.context_processor
def inject_user():
    """Make current user available to all templates"""
    user = None
    if session.get("logged_in"):
        db = get_db_connection()
        if db:
            try:
                cursor = db.cursor()
                cursor.execute("SELECT * FROM users WHERE id = ?", (session.get("user_id"),))
                user = cursor.fetchone()
                db.close()
            except sqlite3.Error:
                pass
    return {'current_user': user}

# ---------------------- DATABASE HELPER FUNCTIONS ---------------------- #

def get_db_connection():
    """Get database connection with error handling"""
    try:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row  # This enables column access by name
        return conn
    except sqlite3.Error as e:
        print(f"Database connection error: {e}")
        return None

def safe_row_get(row, key, default=None):
    """Safely get a value from a sqlite3.Row object"""
    if row is None:
        return default
    try:
        return row[key]
    except (IndexError, KeyError):
        return default

def hash_password(password):
    """Hash password using bcrypt with salt"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# ---------------------- AUDIT LOGGING ---------------------- #

def log_audit(action, table_name, record_id=None, old_values=None, new_values=None):
    """Log user action to audit log"""
    if not session.get("logged_in"):
        return
    
    db = get_db_connection()
    if not db:
        return
    
    try:
        cursor = db.cursor()
        user_id = session.get("user_id")
        username = session.get("username", "unknown")
        ip_address = request.remote_addr if request else None
        
        cursor.execute("""
            INSERT INTO audit_log (user_id, username, action, table_name, record_id, old_values, new_values, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, username, action, table_name, record_id, 
              json.dumps(old_values) if old_values else None,
              json.dumps(new_values) if new_values else None,
              ip_address))
        
        db.commit()
    except sqlite3.Error as e:
        print(f"Audit logging error: {e}")
    finally:
        db.close()

# ---------------------- ROLE-BASED ACCESS CONTROL ---------------------- #

def require_role(*allowed_roles):
    """Decorator to check user role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get("logged_in"):
                flash("Please login first.", "warning")
                return redirect(url_for("login"))
            
            db = get_db_connection()
            if not db:
                flash("Database error.", "danger")
                return redirect(url_for("dashboard"))
            
            try:
                cursor = db.cursor()
                cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
                user = cursor.fetchone()
                db.close()
                
                if not user or safe_row_get(user, 'role') not in allowed_roles:
                    flash("You don't have permission to access this page.", "danger")
                    return redirect(url_for("dashboard"))
                
                return f(*args, **kwargs)
            except sqlite3.Error:
                flash("Database error.", "danger")
                return redirect(url_for("dashboard"))
        
        return decorated_function
    return decorator

def get_advisor_class_filter():
    """Get SQL WHERE clause to filter records by advisor's class"""
    if not session.get("logged_in"):
        return ""
    
    db = get_db_connection()
    if not db:
        return ""
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT role, advisory_class FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        db.close()
        
        # Admins see all records
        if not user or safe_row_get(user, 'role') in ['super_admin', 'health_officer']:
            return ""
        
        # Class advisors see only their class
        if safe_row_get(user, 'role') == 'class_advisor' and safe_row_get(user, 'advisory_class'):
            return f"AND class = '{safe_row_get(user, 'advisory_class')}'"
        
        return ""
    except sqlite3.Error:
        return ""

# ---------------------- AUTH / LOGIN ---------------------- #

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        fullname = request.form.get("fullname", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()
        
        # Validation
        if not all([fullname, username, email, password, confirm_password]):
            flash("All fields are required.", "danger")
            return render_template("register.html")
        
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")
        
        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return render_template("register.html")
        
        # Check if username already exists
        db = get_db_connection()
        if not db:
            flash("Database connection error. Please try again later.", "danger")
            return render_template("register.html")
        
        try:
            cursor = db.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            existing_user = cursor.fetchone()
            
            if existing_user:
                flash("Username already exists. Please choose another.", "danger")
                db.close()
                return render_template("register.html")
            
            # Insert new user
            hashed_password = hash_password(password)
            cursor.execute("""
                INSERT INTO users (username, password, fullname, email)
                VALUES (?, ?, ?, ?)
            """, (username, hashed_password, fullname, email))
            
            db.commit()
            db.close()
            
            flash("Registration successful! You can now login.", "success")
            return redirect(url_for("login"))
            
        except sqlite3.Error as e:
            flash(f"Registration failed: {str(e)}", "danger")
            if db:
                db.close()
            return render_template("register.html")
    
    return render_template("register.html")

@app.route("/api/users", methods=["POST"])
def create_user_api():
    """Create a new user via API (for admin)"""
    print("[API] POST /api/users - User creation request received")
    
    # Check if user is logged in and is super_admin
    if not session.get("logged_in"):
        print("[API] Not logged in")
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        db.close()
        
        if not user or safe_row_get(user, 'role') != 'super_admin':
            print("[API] User is not super_admin")
            return jsonify({'success': False, 'message': 'Only super admin can create users'}), 403
    else:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    data = request.get_json()
    print(f"[API] Data received: {data}")
    
    fullname = data.get("fullname", "").strip()
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    role = data.get("role", "health_officer").strip()
    
    print(f"[API] Parsed values - fullname: {fullname}, username: {username}, email: {email}, role: {role}")
    
    # Validation
    if not all([fullname, username, email, password]):
        print(f"[API] Validation failed - missing required fields")
        return jsonify({'success': False, 'message': 'All fields are required'}), 400
    
    if len(password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
    
    if role not in ROLES:
        return jsonify({'success': False, 'message': 'Invalid role'}), 400
    
    db = get_db_connection()
    if not db:
        return jsonify({'success': False, 'message': 'Database connection error'}), 500
    
    try:
        cursor = db.cursor()
        
        # Check if username exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return jsonify({'success': False, 'message': 'Username already exists'}), 400
        
        # Insert new user
        hashed_password = hash_password(password)
        cursor.execute("""
            INSERT INTO users (username, password, fullname, email, role, is_active)
            VALUES (?, ?, ?, ?, ?, 1)
        """, (username, hashed_password, fullname, email, role))
        
        db.commit()
        
        # Log action
        log_audit("CREATE", "users", cursor.lastrowid, {}, 
                 {'username': username, 'role': role})
        
        db.close()
        
        return jsonify({'success': True, 'message': 'User created successfully'}), 201
        
    except sqlite3.Error as e:
        if db:
            db.close()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        
        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return render_template("index.html")
        
        db = get_db_connection()
        if not db:
            flash("Database connection error. Please try again later.", "danger")
            return render_template("index.html")
        
        try:
            cursor = db.cursor()
            hashed_input_password = hash_password(password)
            cursor.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            )
            user = cursor.fetchone()
            db.close()
            
            if user and bcrypt.checkpw(password.encode(), user["password"].encode()):
                # Check if user account is active
                is_active = safe_row_get(user, 'is_active', 1)
                if not is_active:
                    flash("Your account has been disabled. Please contact the administrator.", "danger")
                    return render_template("index.html")
                
                session["logged_in"] = True
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                # Handle role - use try/except since it might not exist in old databases
                try:
                    session["role"] = safe_row_get(user, "role", "health_officer")
                except (IndexError, KeyError):
                    session["role"] = "health_officer"
                log_audit("LOGIN", "users", user["id"])
                flash(f"Welcome back, {user['fullname']}!", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid username or password.", "danger")
                
        except sqlite3.Error as e:
            flash(f"Login error: {str(e)}", "danger")
            if db:
                db.close()
    
    return render_template("index.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("login"))

# ---------------------- DASHBOARD ---------------------- #

@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    db = get_db_connection()
    if not db:
        flash("Database connection error.", "danger")
        return redirect(url_for("login"))
    
    try:
        cursor = db.cursor()
        
        # Get current user profile
        cursor.execute("SELECT * FROM users WHERE id = ?", (session.get("user_id"),))
        current_user = cursor.fetchone()
        
        # For class advisors, filter by their assigned class
        if current_user and safe_row_get(current_user, 'role') == 'class_advisor' and safe_row_get(current_user, 'advisory_class'):
            advisory_class = safe_row_get(current_user, 'advisory_class')
            
            # Get students from their class
            cursor.execute("SELECT * FROM students WHERE class = ?", (advisory_class,))
            students = cursor.fetchall()
            total_students = len(students)
            total_records = len(
                [s for s in students if s["allergies"] or s["conditions"]]
            )
            
            # Get recent students from their class (last 5 added)
            cursor.execute("""
                SELECT id, studentLRN, name, class, dob 
                FROM students 
                WHERE class = ?
                ORDER BY id DESC 
                LIMIT 5
            """, (advisory_class,))
            recent_students = cursor.fetchall()
            
            # Class advisors don't see teacher data
            teachers = []
            total_teachers = 0
            total_teacher_records = 0
            recent_teachers = []
        else:
            # Admins see all students
            # Get students
            cursor.execute("SELECT * FROM students")
            students = cursor.fetchall()
            total_students = len(students)
            total_records = len(
                [s for s in students if s["allergies"] or s["conditions"]]
            )
            
            # Get recent students (last 5 added)
            cursor.execute("""
                SELECT id, studentLRN, name, class, dob 
                FROM students 
                ORDER BY id DESC 
                LIMIT 5
            """)
            recent_students = cursor.fetchall()
        
        # Get teachers
        cursor.execute("SELECT * FROM teachers")
        teachers = cursor.fetchall()
        total_teachers = len(teachers)
        total_teacher_records = len(
            [t for t in teachers if t["allergies"] or t["conditions"]]
        )
        
        # Get recent teachers (last 5 added)
        cursor.execute("""
            SELECT id, teacherID, name, department, dob 
            FROM teachers 
            ORDER BY id DESC 
            LIMIT 5
        """)
        recent_teachers = cursor.fetchall()
        
        db.close()
        
        return render_template(
            "dashboard.html",
            current_user=current_user,
            total_students=total_students,
            total_records=total_records,
            total_teachers=total_teachers,
            total_teacher_records=total_teacher_records,
            recent_students=recent_students,
            recent_teachers=recent_teachers,
        )
    except sqlite3.Error as e:
        flash(f"Error loading dashboard: {str(e)}", "danger")
        if db:
            db.close()
        return redirect(url_for("login"))

# ---------------------- USER MANAGEMENT ---------------------- #

@app.route("/user-management")
def user_management():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    db = get_db_connection()
    if not db:
        flash("Database connection error.", "danger")
        return redirect(url_for("login"))
    
    try:
        cursor = db.cursor()
        
        # Get all students
        cursor.execute("SELECT * FROM students ORDER BY name")
        students = cursor.fetchall()
        
        # Get all teachers
        cursor.execute("SELECT * FROM teachers ORDER BY name")
        teachers = cursor.fetchall()
        
        db.close()
        
        return render_template(
            "user-management.html",
            students=students,
            teachers=teachers,
        )
    except sqlite3.Error as e:
        flash(f"Error loading user management: {str(e)}", "danger")
        if db:
            db.close()
        return redirect(url_for("login"))

# ---------------------- RECORD LISTS ---------------------- #

@app.route("/record-lists")
def record_lists():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    db = get_db_connection()
    if not db:
        flash("Database connection error.", "danger")
        return redirect(url_for("login"))
    
    try:
        cursor = db.cursor()
        
        # Get user role and advisory class
        cursor.execute("SELECT role, advisory_class FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        
        # Class advisors can only see their own class students, not teachers
        if user and safe_row_get(user, 'role') == 'class_advisor' and safe_row_get(user, 'advisory_class'):
            cursor.execute("SELECT * FROM students WHERE class = ? ORDER BY name", (safe_row_get(user, 'advisory_class'),))
            students = cursor.fetchall()
            teachers = []  # Class advisors cannot see teachers
        else:
            # Admins see all students and teachers
            cursor.execute("SELECT * FROM students ORDER BY name")
            students = cursor.fetchall()
            cursor.execute("SELECT * FROM teachers ORDER BY name")
            teachers = cursor.fetchall()
        
        db.close()
        
        return render_template(
            "record-lists.html",
            students=students,
            teachers=teachers,
        )
    except sqlite3.Error as e:
        flash(f"Error loading record lists: {str(e)}", "danger")
        if db:
            db.close()
        return redirect(url_for("login"))

# ---------------------- ADD STUDENT ---------------------- #

@app.route("/add_student", methods=["GET", "POST"])
def add_student():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    # Check if user is class advisor - they cannot add students
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        db.close()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            flash("You don't have permission to add students.", "danger")
            return redirect(url_for("dashboard"))
    
    if request.method == "POST":
        student_data = (
            request.form.get("studentLRN", "").strip(),
            request.form.get("name", "").strip(),
            request.form.get("class", "").strip(),
            request.form.get("dob") or None,
            request.form.get("address", "").strip() or None,
            request.form.get("parentContact", "").strip() or None,
            request.form.get("emergencyContact", "").strip() or None,
            request.form.get("height", "").strip() or None,
            request.form.get("weight", "").strip() or None,
            request.form.get("blood", "").strip() or None,
            request.form.get("pastIllnesses", "").strip() or None,
            request.form.get("allergies", "").strip() or None,
            request.form.get("conditions", "").strip() or None,
            request.form.get("vaccination", "").strip() or None,
        )
        
        # Validate required fields
        if not student_data[0] or not student_data[1] or not student_data[2]:
            flash("Student LRN, Name, and Class are required fields.", "danger")
            return redirect(url_for("user_management"))
        
        db = get_db_connection()
        if not db:
            flash("Database connection error.", "danger")
            return redirect(url_for("user_management"))
        
        try:
            cursor = db.cursor()
            
            # Check if LRN already exists
            cursor.execute("SELECT id FROM students WHERE studentLRN = ?", (student_data[0],))
            if cursor.fetchone():
                flash("Student with this LRN already exists.", "danger")
                db.close()
                return redirect(url_for("user_management"))
            
            cursor.execute("""
                INSERT INTO students (
                    studentLRN, name, class, dob, address,
                    parentContact, emergencyContact,
                    height, weight, blood,
                    pastIllnesses, allergies, conditions, vaccination
                ) VALUES (?, ?, ?, ?, ?,
                          ?, ?,
                          ?, ?, ?,
                          ?, ?, ?, ?)
            """, student_data)
            
            db.commit()
            db.close()
            
            flash("Student added successfully!", "success")
            return redirect(url_for("user_management"))
            
        except sqlite3.Error as e:
            flash(f"Error adding student: {str(e)}", "danger")
            if db:
                db.close()
            return redirect(url_for("user_management"))
    
    return redirect(url_for("user_management"))

# ---------------------- STUDENT LIST ---------------------- #

@app.route("/students")
def student_list():
    return redirect(url_for("record_lists"))

# ---------------------- STUDENT HEALTH PROFILE ---------------------- #

@app.route("/student/<int:id>")
def student_health(id):
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return redirect(url_for("record_lists"))

# ---------------------- ADD TEACHER ---------------------- #

@app.route("/add_teacher", methods=["GET", "POST"])
def add_teacher():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    # Check if user is class advisor - they cannot add teachers
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        db.close()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            flash("You don't have permission to add teachers.", "danger")
            return redirect(url_for("dashboard"))
    
    if request.method == "POST":
        teacher_data = (
            request.form.get("teacherID", "").strip(),
            request.form.get("name", "").strip(),
            request.form.get("department", "").strip(),
            request.form.get("dob") or None,
            request.form.get("address", "").strip() or None,
            request.form.get("contact", "").strip() or None,
            request.form.get("height", "").strip() or None,
            request.form.get("weight", "").strip() or None,
            request.form.get("blood", "").strip() or None,
            request.form.get("pastIllnesses", "").strip() or None,
            request.form.get("allergies", "").strip() or None,
            request.form.get("conditions", "").strip() or None,
            request.form.get("vaccination", "").strip() or None,
        )
        
        # Validate required fields
        if not teacher_data[0] or not teacher_data[1] or not teacher_data[2]:
            flash("Teacher ID, Name, and Department are required fields.", "danger")
            return redirect(url_for("user_management"))
        
        db = get_db_connection()
        if not db:
            flash("Database connection error.", "danger")
            return redirect(url_for("user_management"))
        
        try:
            cursor = db.cursor()
            
            # Check if Teacher ID already exists
            cursor.execute("SELECT id FROM teachers WHERE teacherID = ?", (teacher_data[0],))
            if cursor.fetchone():
                flash("Teacher with this ID already exists.", "danger")
                db.close()
                return redirect(url_for("user_management"))
            
            cursor.execute("""
                INSERT INTO teachers (
                    teacherID, name, department, dob, address,
                    contact, height, weight, blood,
                    pastIllnesses, allergies, conditions, vaccination
                ) VALUES (?, ?, ?, ?, ?,
                          ?, ?, ?, ?,
                          ?, ?, ?, ?)
            """, teacher_data)
            
            db.commit()
            db.close()
            
            flash("Teacher added successfully!", "success")
            return redirect(url_for("user_management"))
            
        except sqlite3.Error as e:
            flash(f"Error adding teacher: {str(e)}", "danger")
            if db:
                db.close()
            return redirect(url_for("user_management"))
    
    return redirect(url_for("user_management"))

# ---------------------- TEACHER LIST ---------------------- #

@app.route("/teachers")
def teacher_list():
    return redirect(url_for("record_lists"))

# ---------------------- TEACHER HEALTH PROFILE ---------------------- #

@app.route("/teacher/<int:id>")
def teacher_health(id):
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return redirect(url_for("record_lists"))

# ---------------------- DELETE STUDENT ---------------------- #

@app.route("/delete_student/<int:id>", methods=["POST"])
def delete_student(id):
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    # Check if user is class advisor - they cannot delete students
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            flash("You don't have permission to delete students.", "danger")
            db.close()
            return redirect(url_for("dashboard"))
        db.close()
    
    db = get_db_connection()
    if not db:
        flash("Database connection error.", "danger")
        return redirect(url_for("student_list"))
    
    try:
        cursor = db.cursor()
        cursor.execute("DELETE FROM students WHERE id = ?", (id,))
        db.commit()
        db.close()
        
        flash("Student deleted successfully!", "success")
        return redirect(url_for("record_lists"))
    except sqlite3.Error as e:
        flash(f"Error deleting student: {str(e)}", "danger")
        if db:
            db.close()
        return redirect(url_for("record_lists"))

# ---------------------- EDIT STUDENT ---------------------- #

@app.route("/edit_student/<int:id>", methods=["GET", "POST"])
def edit_student(id):
    if not session.get("logged_in"):
        if request.method == "POST":
            return jsonify({"success": False, "message": "Not logged in"}), 401
        return redirect(url_for("login"))
    
    # Check if user is class advisor - they cannot edit students
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            if request.method == "POST":
                return jsonify({"success": False, "message": "You don't have permission to edit students."}), 403
            flash("You don't have permission to edit students.", "danger")
            db.close()
            return redirect(url_for("dashboard"))
        db.close()
    
    db = get_db_connection()
    if not db:
        if request.method == "POST":
            return jsonify({"success": False, "message": "Database connection error"}), 500
        flash("Database connection error.", "danger")
        return redirect(url_for("student_list"))
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM students WHERE id = ?", (id,))
        student = cursor.fetchone()
        
        if not student:
            if request.method == "POST":
                return jsonify({"success": False, "message": "Student not found"}), 404
            flash("Student not found.", "danger")
            db.close()
            return redirect(url_for("record_lists"))
        
        if request.method == "POST":
            student_data = (
                request.form.get("studentLRN", "").strip(),
                request.form.get("name", "").strip(),
                request.form.get("class", "").strip(),
                request.form.get("dob") or None,
                request.form.get("address", "").strip() or None,
                request.form.get("parentContact", "").strip() or None,
                request.form.get("emergencyContact", "").strip() or None,
                request.form.get("height", "").strip() or None,
                request.form.get("weight", "").strip() or None,
                request.form.get("blood", "").strip() or None,
                request.form.get("pastIllnesses", "").strip() or None,
                request.form.get("allergies", "").strip() or None,
                request.form.get("conditions", "").strip() or None,
                request.form.get("vaccination", "").strip() or None,
                id
            )
            
            if not student_data[0] or not student_data[1] or not student_data[2]:
                return jsonify({"success": False, "message": "Student LRN, Name, and Class are required fields."}), 400
            
            cursor.execute("""
                UPDATE students SET
                    studentLRN=?, name=?, class=?, dob=?, address=?,
                    parentContact=?, emergencyContact=?,
                    height=?, weight=?, blood=?,
                    pastIllnesses=?, allergies=?, conditions=?, vaccination=?
                WHERE id=?
            """, student_data)
            
            db.commit()
            db.close()
            
            return jsonify({"success": True, "message": "Student updated successfully!"}), 200
        
        db.close()
        return render_template("edit_student.html", student=student)
        
    except sqlite3.Error as e:
        if request.method == "POST":
            if db:
                db.close()
            return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
        else:
            flash(f"Error: {str(e)}", "danger")
            if db:
                db.close()
            return redirect(url_for("record_lists"))

# ---------------------- DELETE TEACHER ---------------------- #

@app.route("/delete_teacher/<int:id>", methods=["POST"])
def delete_teacher(id):
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    # Check if user is class advisor - they cannot delete teachers
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            flash("You don't have permission to delete teachers.", "danger")
            db.close()
            return redirect(url_for("dashboard"))
        db.close()
    
    db = get_db_connection()
    if not db:
        flash("Database connection error.", "danger")
        return redirect(url_for("teacher_list"))
    
    try:
        cursor = db.cursor()
        cursor.execute("DELETE FROM teachers WHERE id = ?", (id,))
        db.commit()
        db.close()
        
        flash("Teacher deleted successfully!", "success")
        return redirect(url_for("record_lists"))
    except sqlite3.Error as e:
        flash(f"Error deleting teacher: {str(e)}", "danger")
        if db:
            db.close()
        return redirect(url_for("record_lists"))

# ---------------------- EDIT TEACHER ---------------------- #

@app.route("/edit_teacher/<int:id>", methods=["GET", "POST"])
def edit_teacher(id):
    if not session.get("logged_in"):
        if request.method == "POST":
            return jsonify({"success": False, "message": "Not logged in"}), 401
        return redirect(url_for("login"))
    
    # Check if user is class advisor - they cannot edit teachers
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            if request.method == "POST":
                return jsonify({"success": False, "message": "You don't have permission to edit teachers."}), 403
            flash("You don't have permission to edit teachers.", "danger")
            db.close()
            return redirect(url_for("dashboard"))
        db.close()
    
    db = get_db_connection()
    if not db:
        if request.method == "POST":
            return jsonify({"success": False, "message": "Database connection error"}), 500
        flash("Database connection error.", "danger")
        return redirect(url_for("teacher_list"))
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM teachers WHERE id = ?", (id,))
        teacher = cursor.fetchone()
        
        if not teacher:
            if request.method == "POST":
                return jsonify({"success": False, "message": "Teacher not found"}), 404
            flash("Teacher not found.", "danger")
            db.close()
            return redirect(url_for("record_lists"))
        
        if request.method == "POST":
            teacher_data = (
                request.form.get("teacherID", "").strip(),
                request.form.get("name", "").strip(),
                request.form.get("department", "").strip(),
                request.form.get("dob") or None,
                request.form.get("address", "").strip() or None,
                request.form.get("contact", "").strip() or None,
                request.form.get("height", "").strip() or None,
                request.form.get("weight", "").strip() or None,
                request.form.get("blood", "").strip() or None,
                request.form.get("pastIllnesses", "").strip() or None,
                request.form.get("allergies", "").strip() or None,
                request.form.get("conditions", "").strip() or None,
                request.form.get("vaccination", "").strip() or None,
                id
            )
            
            if not teacher_data[0] or not teacher_data[1] or not teacher_data[2]:
                return jsonify({"success": False, "message": "Teacher ID, Name, and Department are required fields."}), 400
            
            cursor.execute("""
                UPDATE teachers SET
                    teacherID=?, name=?, department=?, dob=?, address=?,
                    contact=?, height=?, weight=?, blood=?,
                    pastIllnesses=?, allergies=?, conditions=?, vaccination=?
                WHERE id=?
            """, teacher_data)
            
            db.commit()
            db.close()
            
            return jsonify({"success": True, "message": "Teacher updated successfully!"}), 200
        
        db.close()
        return render_template("edit_teacher.html", teacher=teacher)
        
    except sqlite3.Error as e:
        if request.method == "POST":
            if db:
                db.close()
            return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
        else:
            flash(f"Error: {str(e)}", "danger")
            if db:
                db.close()
            return redirect(url_for("record_lists"))
        if db:
            db.close()
        return redirect(url_for("record_lists"))

# ---------------------- INVENTORY ---------------------- #

@app.route("/inventory")
def inventory():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    db = get_db_connection()
    if not db:
        flash("Database connection error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        
        # Check if user is class advisor - they cannot access inventory
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            db.close()
            flash("You don't have permission to access inventory.", "danger")
            return redirect(url_for("dashboard"))
        
        # Get inventory items
        cursor.execute("SELECT * FROM inventory ORDER BY category, item_name")
        inventory_items = cursor.fetchall()
        db.close()
        
        response = render_template("inventory.html", inventory=inventory_items)
        # Disable caching
        resp = Response(response)
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        return resp
    except sqlite3.Error as e:
        flash(f"Error loading inventory: {str(e)}", "danger")
        if db:
            db.close()
        return redirect(url_for("dashboard"))

# ---------------------- ADD MEDICINE ---------------------- #

@app.route("/add_medicine", methods=["GET", "POST"])
def add_medicine():
    if not session.get("logged_in"):
        return jsonify({"success": False, "message": "Not logged in"}), 401
    
    db = get_db_connection()
    if not db:
        return jsonify({"success": False, "message": "Database connection error"}), 500
    
    try:
        # Check if user is class advisor - they cannot add medicine
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            db.close()
            return jsonify({"success": False, "message": "You don't have permission to add medicine."}), 403
        
        if request.method == "POST":
            item_name = request.form.get("item_name", "").strip()
            category = request.form.get("category", "").strip()
            quantity = request.form.get("quantity", "").strip()
            unit = request.form.get("unit", "").strip()
            status = request.form.get("status", "available").strip()
            expiry_date = request.form.get("expiry_date", "").strip()
            reorder_level = request.form.get("reorder_level", "0").strip()
            supplier = request.form.get("supplier", "").strip()
            notes = request.form.get("notes", "").strip()
            
            # Validation
            if not all([item_name, category, quantity, unit]):
                return jsonify({"success": False, "message": "Please fill in all required fields."}), 400
            
            try:
                quantity = int(quantity)
                reorder_level = int(reorder_level)
            except ValueError:
                return jsonify({"success": False, "message": "Quantity and reorder level must be valid numbers."}), 400
            
            try:
                cursor = db.cursor()
                cursor.execute(
                    """INSERT INTO inventory 
                       (item_name, category, quantity, unit, status, expiry_date, reorder_level, supplier, notes)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (item_name, category, quantity, unit, status, expiry_date or None, reorder_level, supplier, notes)
                )
                db.commit()
                db.close()
                
                return jsonify({"success": True, "message": f"Medicine '{item_name}' added successfully!"}), 200
            except sqlite3.Error as e:
                db.close()
                return jsonify({"success": False, "message": f"Error adding medicine: {str(e)}"}), 500
        
        db.close()
        return render_template("add_medicine.html")
    
    except Exception as e:
        if db:
            db.close()
        return jsonify({"success": False, "message": f"Unexpected error: {str(e)}"}), 500

# ---------------------- DELETE MEDICINE ---------------------- #

@app.route("/delete_medicine/<int:id>", methods=["POST"])
def delete_medicine(id):
    if not session.get("logged_in"):
        return {"success": False, "message": "Not logged in"}, 401
    
    db = get_db_connection()
    if not db:
        return {"success": False, "message": "Database connection error"}, 500
    
    try:
        cursor = db.cursor()
        
        # Check if user is class advisor - they cannot delete medicine
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            db.close()
            return {"success": False, "message": "You don't have permission to delete medicine."}, 403
        
        # Get medicine name before deleting
        cursor.execute("SELECT item_name FROM inventory WHERE id = ?", (id,))
        result = cursor.fetchone()
        
        if result:
            medicine_name = result[0]
            cursor.execute("DELETE FROM inventory WHERE id = ?", (id,))
            db.commit()
            db.close()
            return {"success": True, "message": f"Medicine '{medicine_name}' deleted successfully!"}, 200
        else:
            db.close()
            return {"success": False, "message": "Medicine not found"}, 404
        
    except sqlite3.Error as e:
        if db:
            db.close()
        return {"success": False, "message": f"Error deleting medicine: {str(e)}"}, 500

# ---------------------- NOTIFICATIONS & ALERTS ---------------------- #

def check_missing_health_info():
    """Check for missing health information in student/teacher records"""
    db = get_db_connection()
    if not db:
        return []
    
    try:
        cursor = db.cursor()
        missing_alerts = []
        required_fields = ['blood', 'allergies', 'conditions', 'vaccination', 'height', 'weight']
        
        # Check students
        cursor.execute("SELECT id, name FROM students")
        students = cursor.fetchall()
        for student in students:
            for field in required_fields:
                cursor.execute(f"SELECT {field} FROM students WHERE id = ?", (student[0],))
                result = cursor.fetchone()
                if not result[0] or result[0].strip() == '':
                    missing_alerts.append({
                        'type': 'missing_info',
                        'severity': 'warning',
                        'person_type': 'student',
                        'person_id': student[0],
                        'person_name': student[1],
                        'field': field,
                        'message': f"Student '{student[1]}' is missing {field} information"
                    })
        
        # Check teachers
        cursor.execute("SELECT id, name FROM teachers")
        teachers = cursor.fetchall()
        for teacher in teachers:
            for field in required_fields:
                cursor.execute(f"SELECT {field} FROM teachers WHERE id = ?", (teacher[0],))
                result = cursor.fetchone()
                if not result[0] or result[0].strip() == '':
                    missing_alerts.append({
                        'type': 'missing_info',
                        'severity': 'warning',
                        'person_type': 'teacher',
                        'person_id': teacher[0],
                        'person_name': teacher[1],
                        'field': field,
                        'message': f"Teacher '{teacher[1]}' is missing {field} information"
                    })
        
        db.close()
        return missing_alerts
    
    except sqlite3.Error as e:
        print(f"Error checking missing info: {e}")
        if db:
            db.close()
        return []

def check_expiry_alerts():
    """Check for inventory items nearing or past expiry dates"""
    db = get_db_connection()
    if not db:
        return []
    
    try:
        from datetime import datetime, timedelta
        cursor = db.cursor()
        expiry_alerts = []
        today = datetime.now().date()
        thirty_days = today + timedelta(days=30)
        
        # Check inventory expiry dates
        cursor.execute("""
            SELECT id, item_name, expiry_date, quantity 
            FROM inventory 
            WHERE expiry_date IS NOT NULL
        """)
        items = cursor.fetchall()
        
        for item in items:
            if item[2]:  # if expiry_date exists
                expiry_date = datetime.strptime(item[2], '%Y-%m-%d').date()
                if expiry_date < today:
                    expiry_alerts.append({
                        'type': 'expired',
                        'severity': 'critical',
                        'item_id': item[0],
                        'item_name': item[1],
                        'expiry_date': item[2],
                        'message': f"Item '{item[1]}' has EXPIRED (Expiry: {item[2]})"
                    })
                elif expiry_date <= thirty_days:
                    expiry_alerts.append({
                        'type': 'expiring_soon',
                        'severity': 'warning',
                        'item_id': item[0],
                        'item_name': item[1],
                        'expiry_date': item[2],
                        'message': f"Item '{item[1]}' is expiring soon (Expiry: {item[2]})"
                    })
        
        db.close()
        return expiry_alerts
    
    except Exception as e:
        print(f"Error checking expiry alerts: {e}")
        if db:
            db.close()
        return []

def check_vaccination_schedule():
    """Check for upcoming vaccination dates"""
    db = get_db_connection()
    if not db:
        return []
    
    try:
        from datetime import datetime, timedelta
        cursor = db.cursor()
        vaccination_reminders = []
        today = datetime.now().date()
        
        # Check student vaccinations
        cursor.execute("SELECT id, name, vaccination FROM students WHERE vaccination IS NOT NULL AND vaccination != ''")
        students = cursor.fetchall()
        for student in students:
            # Simple check - if vaccination status contains "pending" or "due"
            vacc_status = student[2].lower()
            if 'pending' in vacc_status or 'due' in vacc_status or 'overdue' in vacc_status:
                vaccination_reminders.append({
                    'type': 'vaccination',
                    'severity': 'info' if 'pending' in vacc_status else 'warning',
                    'person_type': 'student',
                    'person_id': student[0],
                    'person_name': student[1],
                    'vaccination_status': student[2],
                    'message': f"Student '{student[1]}' has vaccination status: {student[2]}"
                })
        
        # Check teacher vaccinations
        cursor.execute("SELECT id, name, vaccination FROM teachers WHERE vaccination IS NOT NULL AND vaccination != ''")
        teachers = cursor.fetchall()
        for teacher in teachers:
            vacc_status = teacher[2].lower()
            if 'pending' in vacc_status or 'due' in vacc_status or 'overdue' in vacc_status:
                vaccination_reminders.append({
                    'type': 'vaccination',
                    'severity': 'info' if 'pending' in vacc_status else 'warning',
                    'person_type': 'teacher',
                    'person_id': teacher[0],
                    'person_name': teacher[1],
                    'vaccination_status': teacher[2],
                    'message': f"Teacher '{teacher[1]}' has vaccination status: {teacher[2]}"
                })
        
        db.close()
        return vaccination_reminders
    
    except Exception as e:
        print(f"Error checking vaccination schedule: {e}")
        if db:
            db.close()
        return []

def get_emergency_contacts():
    """Get emergency contacts for quick access"""
    db = get_db_connection()
    if not db:
        return []
    
    try:
        cursor = db.cursor()
        emergency_data = []
        
        # Get students with emergency contacts
        cursor.execute("""
            SELECT id, name, emergencyContact, parentContact, class 
            FROM students 
            WHERE emergencyContact IS NOT NULL AND emergencyContact != ''
        """)
        students = cursor.fetchall()
        for student in students:
            emergency_data.append({
                'type': 'student',
                'id': student[0],
                'name': student[1],
                'emergency_contact': student[2],
                'parent_contact': student[3],
                'info': student[4],
                'message': f"Student: {student[1]} (Class: {student[4]})"
            })
        
        # Get teachers with emergency contacts
        cursor.execute("""
            SELECT id, name, contact, department 
            FROM teachers 
            WHERE contact IS NOT NULL AND contact != ''
        """)
        teachers = cursor.fetchall()
        for teacher in teachers:
            emergency_data.append({
                'type': 'teacher',
                'id': teacher[0],
                'name': teacher[1],
                'emergency_contact': teacher[2],
                'info': teacher[3],
                'message': f"Teacher: {teacher[1]} (Dept: {teacher[3]})"
            })
        
        db.close()
        return emergency_data
    
    except Exception as e:
        print(f"Error getting emergency contacts: {e}")
        if db:
            db.close()
        return []

@app.route("/notifications", methods=["GET"])
def get_notifications():
    """Get all notifications and alerts for dashboard"""
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    try:
        missing_info = check_missing_health_info()
        expiry_alerts = check_expiry_alerts()
        vaccination_reminders = check_vaccination_schedule()
        emergency_contacts = get_emergency_contacts()
        
        # Combine all alerts
        all_alerts = {
            'missing_info_count': len(missing_info),
            'expiry_alerts_count': len(expiry_alerts),
            'vaccination_reminders_count': len(vaccination_reminders),
            'emergency_contacts_count': len(emergency_contacts),
            'missing_info': missing_info,
            'expiry_alerts': expiry_alerts,
            'vaccination_reminders': vaccination_reminders,
            'emergency_contacts': emergency_contacts
        }
        
        return jsonify(all_alerts), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/alerts_dashboard")
def alerts_dashboard():
    """Display comprehensive alerts and notifications page"""
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    # Check if user is class advisor - they cannot access alerts
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        db.close()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            flash("You don't have permission to access alerts.", "danger")
            return redirect(url_for("dashboard"))
    
    try:
        missing_info = check_missing_health_info()
        expiry_alerts = check_expiry_alerts()
        vaccination_reminders = check_vaccination_schedule()
        emergency_contacts = get_emergency_contacts()
        
        return render_template("alerts.html", 
            missing_info=missing_info,
            expiry_alerts=expiry_alerts,
            vaccination_reminders=vaccination_reminders,
            emergency_contacts=emergency_contacts
        )
    
    except Exception as e:
        flash(f"Error loading alerts: {str(e)}", "danger")
        return redirect(url_for("dashboard"))

# ---------------------- HEALTH ANALYTICS & STATISTICS ---------------------- #

def get_blood_type_distribution():
    """Get blood type distribution for students and teachers"""
    db = get_db_connection()
    if not db:
        return {}
    
    try:
        cursor = db.cursor()
        blood_distribution = {}
        
        # Count student blood types
        cursor.execute("SELECT blood, COUNT(*) as count FROM students WHERE blood IS NOT NULL AND blood != '' GROUP BY blood")
        students_blood = cursor.fetchall()
        
        # Count teacher blood types
        cursor.execute("SELECT blood, COUNT(*) as count FROM teachers WHERE blood IS NOT NULL AND blood != '' GROUP BY blood")
        teachers_blood = cursor.fetchall()
        
        # Combine data
        for blood_type, count in students_blood:
            blood_distribution[blood_type] = blood_distribution.get(blood_type, 0) + count
        
        for blood_type, count in teachers_blood:
            blood_distribution[blood_type] = blood_distribution.get(blood_type, 0) + count
        
        db.close()
        return dict(sorted(blood_distribution.items()))
    
    except Exception as e:
        print(f"Error getting blood type distribution: {e}")
        if db:
            db.close()
        return {}

def get_allergy_statistics():
    """Get common allergies in the system"""
    db = get_db_connection()
    if not db:
        return {}
    
    try:
        cursor = db.cursor()
        allergy_list = []
        
        # Get student allergies
        cursor.execute("SELECT allergies FROM students WHERE allergies IS NOT NULL AND allergies != ''")
        students_allergies = cursor.fetchall()
        
        # Get teacher allergies
        cursor.execute("SELECT allergies FROM teachers WHERE allergies IS NOT NULL AND allergies != ''")
        teachers_allergies = cursor.fetchall()
        
        # Parse and count allergies (they may be comma-separated)
        all_allergies = list(students_allergies) + list(teachers_allergies)
        allergy_count = {}
        
        for record in all_allergies:
            allergies = record[0]
            # Split by comma and clean up
            allergies_list = [a.strip() for a in allergies.split(',')]
            for allergy in allergies_list:
                if allergy:
                    allergy_count[allergy] = allergy_count.get(allergy, 0) + 1
        
        # Sort by count and get top 10
        top_allergies = dict(sorted(allergy_count.items(), key=lambda x: x[1], reverse=True)[:10])
        db.close()
        return top_allergies
    
    except Exception as e:
        print(f"Error getting allergy statistics: {e}")
        if db:
            db.close()
        return {}

def get_vaccination_status():
    """Get vaccination status distribution"""
    db = get_db_connection()
    if not db:
        return {}
    
    try:
        cursor = db.cursor()
        vaccination_status = {}
        
        # Count student vaccination statuses
        cursor.execute("SELECT vaccination, COUNT(*) as count FROM students WHERE vaccination IS NOT NULL AND vaccination != '' GROUP BY vaccination")
        students_vacc = cursor.fetchall()
        
        # Count teacher vaccination statuses
        cursor.execute("SELECT vaccination, COUNT(*) as count FROM teachers WHERE vaccination IS NOT NULL AND vaccination != '' GROUP BY vaccination")
        teachers_vacc = cursor.fetchall()
        
        # Combine
        for vacc_status, count in students_vacc:
            vaccination_status[vacc_status] = vaccination_status.get(vacc_status, 0) + count
        
        for vacc_status, count in teachers_vacc:
            vaccination_status[vacc_status] = vaccination_status.get(vacc_status, 0) + count
        
        db.close()
        return dict(sorted(vaccination_status.items()))
    
    except Exception as e:
        print(f"Error getting vaccination status: {e}")
        if db:
            db.close()
        return {}

def get_past_illnesses_trends():
    """Get frequency of past illnesses"""
    db = get_db_connection()
    if not db:
        return {}
    
    try:
        cursor = db.cursor()
        illness_count = {}
        
        # Get student illnesses
        cursor.execute("SELECT pastIllnesses FROM students WHERE pastIllnesses IS NOT NULL AND pastIllnesses != ''")
        students_illnesses = cursor.fetchall()
        
        # Get teacher illnesses
        cursor.execute("SELECT pastIllnesses FROM teachers WHERE pastIllnesses IS NOT NULL AND pastIllnesses != ''")
        teachers_illnesses = cursor.fetchall()
        
        # Parse and count illnesses (may be comma-separated)
        all_illnesses = list(students_illnesses) + list(teachers_illnesses)
        
        for record in all_illnesses:
            illnesses = record[0]
            # Split by comma and clean up
            illness_list = [i.strip() for i in illnesses.split(',')]
            for illness in illness_list:
                if illness:
                    illness_count[illness] = illness_count.get(illness, 0) + 1
        
        # Sort by count and get top 10
        top_illnesses = dict(sorted(illness_count.items(), key=lambda x: x[1], reverse=True)[:10])
        db.close()
        return top_illnesses
    
    except Exception as e:
        print(f"Error getting illness trends: {e}")
        if db:
            db.close()
        return {}

def get_health_conditions_stats():
    """Get statistics on pre-existing health conditions"""
    db = get_db_connection()
    if not db:
        return {}
    
    try:
        cursor = db.cursor()
        conditions_count = {}
        
        # Get student conditions
        cursor.execute("SELECT conditions FROM students WHERE conditions IS NOT NULL AND conditions != ''")
        students_conditions = cursor.fetchall()
        
        # Get teacher conditions
        cursor.execute("SELECT conditions FROM teachers WHERE conditions IS NOT NULL AND conditions != ''")
        teachers_conditions = cursor.fetchall()
        
        # Parse and count conditions
        all_conditions = list(students_conditions) + list(teachers_conditions)
        
        for record in all_conditions:
            conditions = record[0]
            # Split by comma and clean up
            condition_list = [c.strip() for c in conditions.split(',')]
            for condition in condition_list:
                if condition:
                    conditions_count[condition] = conditions_count.get(condition, 0) + 1
        
        # Sort by count and get top 10
        top_conditions = dict(sorted(conditions_count.items(), key=lambda x: x[1], reverse=True)[:10])
        db.close()
        return top_conditions
    
    except Exception as e:
        print(f"Error getting conditions stats: {e}")
        if db:
            db.close()
        return {}

def get_health_summary():
    """Get overall health summary statistics"""
    db = get_db_connection()
    if not db:
        return {}
    
    try:
        cursor = db.cursor()
        
        # Count total students and teachers
        cursor.execute("SELECT COUNT(*) as count FROM students")
        total_students = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) as count FROM teachers")
        total_teachers = cursor.fetchone()[0]
        
        # Count students with allergies
        cursor.execute("SELECT COUNT(*) as count FROM students WHERE allergies IS NOT NULL AND allergies != ''")
        students_with_allergies = cursor.fetchone()[0]
        
        # Count students with pre-existing conditions
        cursor.execute("SELECT COUNT(*) as count FROM students WHERE conditions IS NOT NULL AND conditions != ''")
        students_with_conditions = cursor.fetchone()[0]
        
        # Count teachers with allergies
        cursor.execute("SELECT COUNT(*) as count FROM teachers WHERE allergies IS NOT NULL AND allergies != ''")
        teachers_with_allergies = cursor.fetchone()[0]
        
        # Count teachers with pre-existing conditions
        cursor.execute("SELECT COUNT(*) as count FROM teachers WHERE conditions IS NOT NULL AND conditions != ''")
        teachers_with_conditions = cursor.fetchone()[0]
        
        # Count pending vaccinations
        cursor.execute("SELECT COUNT(*) as count FROM students WHERE vaccination LIKE '%pending%' OR vaccination LIKE '%due%'")
        pending_vaccinations = cursor.fetchone()[0]
        
        # Get inventory alerts
        from datetime import datetime, timedelta
        today = datetime.now().date()
        cursor.execute("SELECT COUNT(*) as count FROM inventory WHERE expiry_date IS NOT NULL AND expiry_date < ?", (str(today),))
        expired_items = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) as count FROM inventory WHERE expiry_date IS NOT NULL AND expiry_date BETWEEN ? AND ?", 
                      (str(today), str(today + timedelta(days=30))))
        expiring_soon = cursor.fetchone()[0]
        
        db.close()
        
        return {
            'total_students': total_students,
            'total_teachers': total_teachers,
            'students_with_allergies': students_with_allergies,
            'students_with_conditions': students_with_conditions,
            'teachers_with_allergies': teachers_with_allergies,
            'teachers_with_conditions': teachers_with_conditions,
            'pending_vaccinations': pending_vaccinations,
            'expired_items': expired_items,
            'expiring_soon': expiring_soon
        }
    
    except Exception as e:
        print(f"Error getting health summary: {e}")
        if db:
            db.close()
        return {}

@app.route("/analytics", methods=["GET"])
def analytics():
    """Display comprehensive health analytics dashboard"""
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    # Check if user is class advisor - they cannot access analytics
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        db.close()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            flash("You don't have permission to access analytics.", "danger")
            return redirect(url_for("dashboard"))
    
    try:
        # Get all analytics data
        blood_distribution = get_blood_type_distribution()
        allergies = get_allergy_statistics()
        vaccination_status = get_vaccination_status()
        illnesses = get_past_illnesses_trends()
        conditions = get_health_conditions_stats()
        summary = get_health_summary()
        
        return render_template("analytics.html",
            blood_distribution=blood_distribution,
            allergies=allergies,
            vaccination_status=vaccination_status,
            illnesses=illnesses,
            conditions=conditions,
            summary=summary
        )
    
    except Exception as e:
        flash(f"Error loading analytics: {str(e)}", "danger")
        return redirect(url_for("dashboard"))

@app.route("/api/analytics/json", methods=["GET"])
def analytics_json():
    """API endpoint to get all analytics data as JSON"""
    if not session.get("logged_in"):
        return jsonify({"error": "Not logged in"}), 401
    
    try:
        blood_distribution = get_blood_type_distribution()
        allergies = get_allergy_statistics()
        vaccination_status = get_vaccination_status()
        illnesses = get_past_illnesses_trends()
        conditions = get_health_conditions_stats()
        summary = get_health_summary()
        
        return jsonify({
            'blood_distribution': blood_distribution,
            'allergies': allergies,
            'vaccination_status': vaccination_status,
            'illnesses': illnesses,
            'conditions': conditions,
            'summary': summary
        }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------------- REPORTS & EXPORT ---------------------- #

def generate_csv_export(data_type, data):
    """Generate CSV format for export"""
    import csv
    import io
    from datetime import datetime
    
    output = io.StringIO()
    
    if data_type == 'students':
        writer = csv.writer(output)
        writer.writerow(['ID', 'LRN', 'Name', 'Class', 'DOB', 'Blood Type', 'Allergies', 'Conditions', 'Vaccination'])
        for student in data:
            writer.writerow([
                student['id'], student['studentLRN'], student['name'], student['class'],
                student['dob'], student['blood'], student['allergies'], student['conditions'], student['vaccination']
            ])
    
    elif data_type == 'teachers':
        writer = csv.writer(output)
        writer.writerow(['ID', 'Teacher Code', 'Name', 'Department', 'DOB', 'Blood Type', 'Allergies', 'Conditions', 'Contact'])
        for teacher in data:
            writer.writerow([
                teacher['id'], teacher['teacherID'], teacher['name'], teacher['department'],
                teacher['dob'], teacher['blood'], teacher['allergies'], teacher['conditions'], teacher['contact']
            ])
    
    elif data_type == 'inventory':
        writer = csv.writer(output)
        writer.writerow(['ID', 'Item Name', 'Category', 'Quantity', 'Unit', 'Status', 'Expiry Date', 'Reorder Level', 'Supplier'])
        for item in data:
            writer.writerow([
                item['id'], item['item_name'], item['category'], item['quantity'],
                item['unit'], item['status'], item['expiry_date'], item['reorder_level'], item['supplier']
            ])
    
    return output.getvalue()

def get_class_health_overview(class_name):
    """Get health overview for a specific class"""
    db = get_db_connection()
    if not db:
        return None
    
    try:
        cursor = db.cursor()
        
        # Get all students in the class
        cursor.execute("SELECT * FROM students WHERE class = ?", (class_name,))
        students = cursor.fetchall()
        
        # Calculate statistics
        total_students = len(students)
        students_with_allergies = sum(1 for s in students if s['allergies'] and s['allergies'].strip())
        students_with_conditions = sum(1 for s in students if s['conditions'] and s['conditions'].strip())
        vaccination_statuses = {}
        blood_types = {}
        
        for student in students:
            # Count vaccinations
            vacc = student['vaccination']
            if vacc:
                vaccination_statuses[vacc] = vaccination_statuses.get(vacc, 0) + 1
            
            # Count blood types
            blood = student['blood']
            if blood:
                blood_types[blood] = blood_types.get(blood, 0) + 1
        
        db.close()
        
        return {
            'class_name': class_name,
            'total_students': total_students,
            'students_with_allergies': students_with_allergies,
            'students_with_conditions': students_with_conditions,
            'vaccination_statuses': vaccination_statuses,
            'blood_types': blood_types,
            'students': students
        }
    
    except Exception as e:
        print(f"Error getting class health overview: {e}")
        if db:
            db.close()
        return None

def get_inventory_report():
    """Generate inventory report with stock levels and status"""
    db = get_db_connection()
    if not db:
        return {}
    
    try:
        cursor = db.cursor()
        
        # Get all inventory items
        cursor.execute("""
            SELECT id, item_name, category, quantity, unit, status, expiry_date, reorder_level, supplier
            FROM inventory
            ORDER BY status, category
        """)
        
        items = cursor.fetchall()
        
        # Categorize items
        low_stock = []
        expiring_soon = []
        expired = []
        in_stock = []
        
        from datetime import datetime, timedelta
        today = datetime.now().date()
        
        for item in items:
            item_dict = {
                'id': item['id'],
                'item_name': item['item_name'],
                'category': item['category'],
                'quantity': item['quantity'],
                'unit': item['unit'],
                'status': item['status'],
                'expiry_date': item['expiry_date'],
                'reorder_level': item['reorder_level'],
                'supplier': item['supplier']
            }
            
            # Check stock levels
            if item['quantity'] and item['reorder_level'] and item['quantity'] <= item['reorder_level']:
                low_stock.append(item_dict)
            
            # Check expiry dates
            if item['expiry_date']:
                expiry_date = datetime.strptime(item['expiry_date'], '%Y-%m-%d').date()
                if expiry_date < today:
                    expired.append(item_dict)
                elif expiry_date <= today + timedelta(days=30):
                    expiring_soon.append(item_dict)
            
            if item['status'] == 'available' and item['quantity'] and item['quantity'] > item['reorder_level']:
                in_stock.append(item_dict)
        
        db.close()
        
        return {
            'low_stock': low_stock,
            'expiring_soon': expiring_soon,
            'expired': expired,
            'in_stock': in_stock,
            'total_items': len(items),
            'critical_items': len(low_stock) + len(expired)
        }
    
    except Exception as e:
        print(f"Error generating inventory report: {e}")
        if db:
            db.close()
        return {}

@app.route("/reports", methods=["GET"])
def reports():
    """Display reports and export options"""
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    # Check if user is class advisor - they cannot access reports
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        db.close()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            flash("You don't have permission to access reports.", "danger")
            return redirect(url_for("dashboard"))
    
    try:
        db = get_db_connection()
        if not db:
            flash("Database connection error.", "danger")
            return redirect(url_for("dashboard"))
        
        cursor = db.cursor()
        
        # Get list of classes
        cursor.execute("SELECT DISTINCT class FROM students ORDER BY class")
        classes = [row[0] for row in cursor.fetchall()]
        
        # Get inventory report
        inventory_report = get_inventory_report()
        
        db.close()
        
        return render_template("reports.html", 
            classes=classes,
            inventory_report=inventory_report
        )
    
    except Exception as e:
        flash(f"Error loading reports: {str(e)}", "danger")
        return redirect(url_for("dashboard"))

@app.route("/export/students/<export_format>", methods=["GET"])
def export_students(export_format):
    """Export student health records"""
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    try:
        db = get_db_connection()
        if not db:
            return jsonify({"error": "Database connection error"}), 500
        
        cursor = db.cursor()
        cursor.execute("SELECT * FROM students")
        students = [dict(row) for row in cursor.fetchall()]
        db.close()
        
        if export_format == 'csv':
            csv_data = generate_csv_export('students', students)
            return Response(
                csv_data,
                mimetype="text/csv",
                headers={"Content-disposition": "attachment;filename=students_health_records.csv"}
            )
        
        return jsonify({"error": "Unsupported format"}), 400
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/export/teachers/<export_format>", methods=["GET"])
def export_teachers(export_format):
    """Export teacher health records"""
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    try:
        db = get_db_connection()
        if not db:
            return jsonify({"error": "Database connection error"}), 500
        
        cursor = db.cursor()
        cursor.execute("SELECT * FROM teachers")
        teachers = [dict(row) for row in cursor.fetchall()]
        db.close()
        
        if export_format == 'csv':
            csv_data = generate_csv_export('teachers', teachers)
            return Response(
                csv_data,
                mimetype="text/csv",
                headers={"Content-disposition": "attachment;filename=teachers_health_records.csv"}
            )
        
        return jsonify({"error": "Unsupported format"}), 400
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/export/inventory/<export_format>", methods=["GET"])
def export_inventory(export_format):
    """Export inventory report"""
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    try:
        db = get_db_connection()
        if not db:
            return jsonify({"error": "Database connection error"}), 500
        
        cursor = db.cursor()
        cursor.execute("SELECT * FROM inventory ORDER BY category")
        inventory = [dict(row) for row in cursor.fetchall()]
        db.close()
        
        if export_format == 'csv':
            csv_data = generate_csv_export('inventory', inventory)
            return Response(
                csv_data,
                mimetype="text/csv",
                headers={"Content-disposition": "attachment;filename=inventory_report.csv"}
            )
        
        return jsonify({"error": "Unsupported format"}), 400
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/class-health-report/<class_name>", methods=["GET"])
def class_health_report(class_name):
    """Generate health report for a specific class"""
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    try:
        report = get_class_health_overview(class_name)
        if not report:
            flash("Class not found.", "danger")
            return redirect(url_for("reports"))
        
        return render_template("class_health_report.html", report=report)
    
    except Exception as e:
        flash(f"Error generating class report: {str(e)}", "danger")
        return redirect(url_for("reports"))

# ---------------------- ADVANCED MANAGEMENT ---------------------- #

@app.route("/advanced-management")
@require_role('super_admin', 'health_officer')
def advanced_management():
    """Advanced management dashboard"""
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        
        # Get user statistics
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE is_active = 1")
        total_users = cursor.fetchone()['count']
        
        # Get recent audit logs
        cursor.execute("""
            SELECT * FROM audit_log 
            ORDER BY timestamp DESC 
            LIMIT 20
        """)
        recent_logs = cursor.fetchall()
        
        # Get backup history
        cursor.execute("""
            SELECT * FROM backup_log 
            ORDER BY created_at DESC 
            LIMIT 10
        """)
        backups = cursor.fetchall()
        
        db.close()
        
        return render_template("advanced_management.html", 
                             total_users=total_users,
                             recent_logs=recent_logs,
                             backups=backups,
                             roles=ROLES)
    except sqlite3.Error as e:
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for("dashboard"))

# ---------------------- USER ROLE MANAGEMENT ---------------------- #

@app.route("/manage-users")
@require_role('super_admin')
def manage_users():
    """Manage user roles and permissions"""
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users ORDER BY created_at DESC")
        users = cursor.fetchall()
        
        # Get list of classes for assignment
        cursor.execute("SELECT DISTINCT class FROM students ORDER BY class")
        classes = [row[0] for row in cursor.fetchall()]
        
        db.close()
        
        return render_template("manage_users.html", users=users, roles=ROLES, classes=classes)
    except sqlite3.Error as e:
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for("advanced_management"))

@app.route("/api/user/<int:user_id>/role", methods=["POST"])
def update_user_role(user_id):
    """Update user role"""
    # Check if user is logged in and is super_admin
    if not session.get("logged_in"):
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        db.close()
        
        if not user or safe_row_get(user, 'role') != 'super_admin':
            return jsonify({'success': False, 'message': 'Only super admin can update roles'}), 403
    else:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    data = request.get_json()
    new_role = data.get('role')
    
    if new_role not in ROLES:
        return jsonify({'success': False, 'message': 'Invalid role'}), 400
    
    db = get_db_connection()
    if not db:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    try:
        cursor = db.cursor()
        
        # Get old role for audit
        cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        old_data = cursor.fetchone()
        old_role = old_data['role'] if old_data else None
        
        # Update role
        cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        db.commit()
        
        # Audit log
        log_audit("UPDATE", "users", user_id, 
                 {'role': old_role}, 
                 {'role': new_role})
        
        db.close()
        return jsonify({'success': True, 'message': 'Role updated successfully'})
    except sqlite3.Error as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route("/api/user/<int:user_id>/advisory-class", methods=["POST"])
def update_advisory_class(user_id):
    """Update class advisor's assigned advisory class"""
    print(f"[API] POST /api/user/{user_id}/advisory-class - Advisory class assignment request")
    
    # Check if user is logged in and is super_admin
    if not session.get("logged_in"):
        print("[API] Not logged in")
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        db.close()
        
        if not user or safe_row_get(user, 'role') != 'super_admin':
            print(f"[API] User {session.get('user_id')} is not super_admin")
            return jsonify({'success': False, 'message': 'Only super admin can assign advisory classes'}), 403
    else:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    data = request.get_json()
    advisory_class = data.get('advisory_class', '').strip()
    print(f"[API] Advisory class to assign: '{advisory_class}'")
    
    db = get_db_connection()
    if not db:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    try:
        cursor = db.cursor()
        
        # Verify user exists and has class_advisor role
        cursor.execute("SELECT role, advisory_class FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            print(f"[API] User {user_id} not found")
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        if safe_row_get(user, 'role') != 'class_advisor':
            print(f"[API] User {user_id} is not a class_advisor, role is {safe_row_get(user, 'role')}")
            return jsonify({'success': False, 'message': 'User is not a class advisor'}), 400
        
        old_advisory_class = safe_row_get(user, 'advisory_class')
        print(f"[API] Old advisory class: {old_advisory_class}, New: {advisory_class}")
        
        # Update advisory class
        cursor.execute("UPDATE users SET advisory_class = ? WHERE id = ?", (advisory_class or None, user_id))
        db.commit()
        
        # Verify update
        cursor.execute("SELECT advisory_class FROM users WHERE id = ?", (user_id,))
        updated = cursor.fetchone()
        print(f"[API] After update - advisory_class in DB: {updated[0] if updated else 'NOT FOUND'}")
        
        # Audit log
        log_audit("UPDATE", "users", user_id, 
                 {'advisory_class': old_advisory_class}, 
                 {'advisory_class': advisory_class})
        
        db.close()
        print(f"[API] Successfully updated user {user_id} advisory class to '{advisory_class}'")
        return jsonify({'success': True, 'message': f'Advisory class updated to {advisory_class if advisory_class else "None"}'})
    except sqlite3.Error as e:
        print(f"[API] Database error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route("/api/user/<int:user_id>/status", methods=["POST"])
def update_user_status(user_id):
    """Activate/deactivate user"""
    # Check if user is logged in and is super_admin
    if not session.get("logged_in"):
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        db.close()
        
        if not user or safe_row_get(user, 'role') != 'super_admin':
            return jsonify({'success': False, 'message': 'Only super admin can change user status'}), 403
    else:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    data = request.get_json()
    is_active = data.get('is_active')
    
    db = get_db_connection()
    if not db:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    try:
        cursor = db.cursor()
        cursor.execute("UPDATE users SET is_active = ? WHERE id = ?", (1 if is_active else 0, user_id))
        db.commit()
        
        log_audit("UPDATE", "users", user_id, {}, {'is_active': is_active})
        
        db.close()
        return jsonify({'success': True, 'message': 'User status updated'})
    except sqlite3.Error as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# ---------------------- AUDIT LOG VIEWING ---------------------- #

@app.route("/audit-logs")
@require_role('super_admin', 'health_officer')
def audit_logs():
    """View audit logs"""
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        
        # Get total count
        cursor.execute("SELECT COUNT(*) as count FROM audit_log")
        total = cursor.fetchone()['count']
        
        # Get paginated logs
        offset = (page - 1) * per_page
        cursor.execute("""
            SELECT * FROM audit_log 
            ORDER BY timestamp DESC 
            LIMIT ? OFFSET ?
        """, (per_page, offset))
        logs = cursor.fetchall()
        
        db.close()
        
        total_pages = (total + per_page - 1) // per_page
        
        return render_template("audit_logs.html", 
                             logs=logs,
                             page=page,
                             total_pages=total_pages,
                             total=total)
    except sqlite3.Error as e:
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for("advanced_management"))

# ---------------------- BULK IMPORT/EXPORT ---------------------- #

@app.route("/import-export")
@require_role('super_admin', 'health_officer')
def import_export():
    """Bulk import/export page"""
    return render_template("import_export.html")

@app.route("/api/export/students", methods=["GET"])
@require_role('super_admin', 'health_officer')
def export_students_csv():
    """Export students to CSV"""
    db = get_db_connection()
    if not db:
        return "Database error", 500
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM students ORDER BY name")
        students = cursor.fetchall()
        db.close()
        
        # Create CSV
        output = io.StringIO()
        if students:
            writer = csv.DictWriter(output, fieldnames=[d[0] for d in cursor.description] if cursor.description else [])
            writer.writeheader()
            for student in students:
                writer.writerow(dict(student))
        
        log_audit("EXPORT", "students", None, {}, {'count': len(students)})
        
        response = Response(output.getvalue(), mimetype="text/csv")
        response.headers["Content-Disposition"] = "attachment;filename=students.csv"
        return response
    except sqlite3.Error as e:
        return f"Error: {str(e)}", 500

@app.route("/api/export/teachers", methods=["GET"])
@require_role('super_admin', 'health_officer')
def export_teachers_csv():
    """Export teachers to CSV"""
    db = get_db_connection()
    if not db:
        return "Database error", 500
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM teachers ORDER BY name")
        teachers = cursor.fetchall()
        db.close()
        
        # Create CSV
        output = io.StringIO()
        if teachers:
            writer = csv.DictWriter(output, fieldnames=[d[0] for d in cursor.description] if cursor.description else [])
            writer.writeheader()
            for teacher in teachers:
                writer.writerow(dict(teacher))
        
        log_audit("EXPORT", "teachers", None, {}, {'count': len(teachers)})
        
        response = Response(output.getvalue(), mimetype="text/csv")
        response.headers["Content-Disposition"] = "attachment;filename=teachers.csv"
        return response
    except sqlite3.Error as e:
        return f"Error: {str(e)}", 500

@app.route("/api/import/students", methods=["POST"])
@require_role('super_admin', 'health_officer')
def import_students_csv():
    """Import students from CSV"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    if not file.filename.endswith('.csv'):
        return jsonify({'success': False, 'message': 'Only CSV files allowed'}), 400
    
    try:
        db = get_db_connection()
        cursor = db.cursor()
        
        # Parse CSV
        stream = io.TextIOWrapper(file.stream, encoding='utf-8')
        reader = csv.DictReader(stream)
        
        imported_count = 0
        errors = []
        
        for row in reader:
            try:
                cursor.execute("""
                    INSERT OR REPLACE INTO students 
                    (studentLRN, name, class, dob, address, parentContact, emergencyContact, 
                     height, weight, blood, pastIllnesses, allergies, conditions, vaccination)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    row.get('studentLRN'),
                    row.get('name'),
                    row.get('class'),
                    row.get('dob'),
                    row.get('address'),
                    row.get('parentContact'),
                    row.get('emergencyContact'),
                    row.get('height'),
                    row.get('weight'),
                    row.get('blood'),
                    row.get('pastIllnesses'),
                    row.get('allergies'),
                    row.get('conditions'),
                    row.get('vaccination')
                ))
                imported_count += 1
            except Exception as e:
                errors.append(f"Row error: {str(e)}")
        
        db.commit()
        log_audit("IMPORT", "students", None, {}, {'count': imported_count})
        db.close()
        
        return jsonify({
            'success': True, 
            'message': f'Imported {imported_count} students',
            'errors': errors
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route("/api/import/teachers", methods=["POST"])
@require_role('super_admin', 'health_officer')
def import_teachers_csv():
    """Import teachers from CSV"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    if not file.filename.endswith('.csv'):
        return jsonify({'success': False, 'message': 'Only CSV files allowed'}), 400
    
    try:
        db = get_db_connection()
        cursor = db.cursor()
        
        # Parse CSV
        stream = io.TextIOWrapper(file.stream, encoding='utf-8')
        reader = csv.DictReader(stream)
        
        imported_count = 0
        errors = []
        
        for row in reader:
            try:
                cursor.execute("""
                    INSERT OR REPLACE INTO teachers 
                    (teacherID, name, department, dob, address, contact, 
                     height, weight, blood, pastIllnesses, allergies, conditions, vaccination)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    row.get('teacherID'),
                    row.get('name'),
                    row.get('department'),
                    row.get('dob'),
                    row.get('address'),
                    row.get('contact'),
                    row.get('height'),
                    row.get('weight'),
                    row.get('blood'),
                    row.get('pastIllnesses'),
                    row.get('allergies'),
                    row.get('conditions'),
                    row.get('vaccination')
                ))
                imported_count += 1
            except Exception as e:
                errors.append(f"Row error: {str(e)}")
        
        db.commit()
        log_audit("IMPORT", "teachers", None, {}, {'count': imported_count})
        db.close()
        
        return jsonify({
            'success': True, 
            'message': f'Imported {imported_count} teachers',
            'errors': errors
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# ---------------------- BACKUP & RESTORE ---------------------- #

@app.route("/api/backup/create", methods=["POST"])
@require_role('super_admin', 'health_officer')
def create_backup():
    """Create database backup"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"backup_{timestamp}.db"
        backup_path = os.path.join(BACKUP_DIR, backup_name)
        
        # Copy database file
        shutil.copy2(DATABASE, backup_path)
        
        # Log backup
        db = get_db_connection()
        cursor = db.cursor()
        
        backup_size = os.path.getsize(backup_path)
        cursor.execute("""
            INSERT INTO backup_log (backup_name, backup_path, backup_size, backup_type, created_by)
            VALUES (?, ?, ?, ?, ?)
        """, (backup_name, backup_path, backup_size, 'manual', session.get('user_id')))
        
        db.commit()
        log_audit("BACKUP_CREATE", "backup_log", None, {}, {'backup': backup_name})
        db.close()
        
        return jsonify({
            'success': True, 
            'message': f'Backup created: {backup_name}'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route("/api/backup/restore/<backup_name>", methods=["POST"])
@require_role('super_admin')
def restore_backup(backup_name):
    """Restore from backup"""
    try:
        backup_path = os.path.join(BACKUP_DIR, backup_name)
        
        if not os.path.exists(backup_path):
            return jsonify({'success': False, 'message': 'Backup file not found'}), 404
        
        # Create safety backup before restore
        safety_backup = os.path.join(BACKUP_DIR, f"safety_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db")
        shutil.copy2(DATABASE, safety_backup)
        
        # Restore
        shutil.copy2(backup_path, DATABASE)
        
        db = get_db_connection()
        cursor = db.cursor()
        log_audit("BACKUP_RESTORE", "backup_log", None, {'backup': backup_name}, {})
        db.close()
        
        return jsonify({
            'success': True, 
            'message': f'Restored from {backup_name}. Safety backup at {os.path.basename(safety_backup)}'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route("/api/backup/delete/<backup_name>", methods=["POST"])
@require_role('super_admin')
def delete_backup(backup_name):
    """Delete a backup file"""
    try:
        backup_path = os.path.join(BACKUP_DIR, backup_name)
        
        # Prevent deletion of the main database file
        if backup_name == DATABASE or backup_path == DATABASE:
            return jsonify({'success': False, 'message': 'Cannot delete the main database'}), 400
        
        if not os.path.exists(backup_path):
            return jsonify({'success': False, 'message': 'Backup file not found'}), 404
        
        # Delete the backup file
        os.remove(backup_path)
        
        # Remove from backup_log database
        db = get_db_connection()
        if db:
            try:
                cursor = db.cursor()
                cursor.execute("DELETE FROM backup_log WHERE backup_name = ?", (backup_name,))
                log_audit("BACKUP_DELETE", "backup_log", None, {'backup': backup_name}, {})
                db.commit()
                db.close()
            except sqlite3.Error:
                db.close()
        
        return jsonify({
            'success': True, 
            'message': f'Backup {backup_name} deleted successfully'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route("/backups")
@require_role('super_admin')
def view_backups():
    """View all backups"""
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM backup_log ORDER BY created_at DESC")
        backups = cursor.fetchall()
        db.close()
        
        # Get file info for each backup
        backup_info = []
        for backup in backups:
            if os.path.exists(backup['backup_path']):
                size = os.path.getsize(backup['backup_path'])
                backup_info.append({
                    **dict(backup),
                    'file_size': f"{size / 1024 / 1024:.2f} MB"
                })
        
        return render_template("backups.html", backups=backup_info)
    except sqlite3.Error as e:
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for("dashboard"))

# ---------------------- MAIN ---------------------- #

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)