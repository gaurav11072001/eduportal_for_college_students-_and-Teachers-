from flask import Flask, render_template, redirect, url_for, request, session, flash,send_file, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from flask_wtf.csrf import CSRFProtect
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import json
from urllib.parse import unquote
from sqlalchemy import inspect, text

app = Flask(__name__)
# Use a fixed secret key for development
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eduportal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Set session lifetime to 7 days
app.config['SESSION_TYPE'] = 'filesystem'  # Store sessions in filesystem
app.config['SESSION_PERMANENT'] = True  # Make sessions permanent by default

# Only enable secure cookie in production
if not app.debug:  # Production mode
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
else:  # Development mode
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = 'Please log in to access this page.'
login_manager.session_protection = 'strong'  # Enable strong session protection

# Define decorator functions before routes
def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'teacher':
            flash('Access denied. Teachers only.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def student_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'student':
            flash('Access denied. Students only.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'pdf'}
app.config['UPLOAD_FOLDE'] = 'static'

# Define User model
class User(UserMixin, db.Model):
    __tablename__ = 'users'  # Explicitly set table name
    
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    branch = db.Column(db.String(50), nullable=True)
    semester = db.Column(db.String(20), nullable=True)
    department = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scores = db.relationship('Score', backref='user', lazy=True)
    notices = db.relationship('Notice', backref='author', lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password, method='pbkdf2:sha256:260000')

    def check_password(self, password):
        return check_password_hash(self.password, password)

# Define SportsEvent model
class SportsEvent(db.Model):
    __tablename__ = 'sports_events'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    event_date = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    image_path = db.Column(db.String(200), nullable=True)
    participants = db.relationship('Participant', backref='sports_event', lazy=True)

# Participant Model
class Participant(db.Model):
    __tablename__ = 'participants'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    branch = db.Column(db.String(50), nullable=False)
    semester = db.Column(db.String(20), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    event_id = db.Column(db.Integer, db.ForeignKey('sports_events.id'), nullable=False)

# Define Question model with MCQ support
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.String(200), nullable=False)
    option1 = db.Column(db.String(100), nullable=False)
    option2 = db.Column(db.String(100), nullable=False)
    option3 = db.Column(db.String(100), nullable=False)
    option4 = db.Column(db.String(100), nullable=False)
    correct_answer = db.Column(db.String(100), nullable=False)
    time_limit = db.Column(db.Integer, default=30)  # Time limit per question in minutes
    exam_time_limit = db.Column(db.Integer, default=60)  # Total exam time limit in minutes

class Score(db.Model):
    __tablename__ = 'scores'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    marks = db.Column(db.Float, nullable=False)
    max_marks = db.Column(db.Float, nullable=False)
    exam_date = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Initialize database and create a default teacher user
class ExamScore(db.Model):
    __tablename__ = 'exam_scores'
    
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    marks = db.Column(db.Float, nullable=False)
    max_marks = db.Column(db.Float, nullable=False)
    exam_date = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    questions_attempted = db.Column(db.Text, nullable=False, default='')
    student = db.relationship('User', backref='exam_scores')

class SemesterResult(db.Model):
    __tablename__ = 'semester_results'
    
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    semester = db.Column(db.String(20), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    marks = db.Column(db.Float, nullable=False)
    max_marks = db.Column(db.Float, nullable=False)
    grade = db.Column(db.String(2))  # A+, A, B+, B, etc.
    result_date = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    marksheet_file = db.Column(db.String(200))  # Path to uploaded marksheet file
    verified = db.Column(db.Boolean, default=False)  # New field to indicate verification status
    verified_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Teacher who verified
    verified_at = db.Column(db.DateTime, nullable=True)  # When it was verified
    
    # Define relationships
    student = db.relationship('User', foreign_keys=[student_id], backref='semester_results')
    teacher = db.relationship('User', foreign_keys=[created_by])
    verifier = db.relationship('User', foreign_keys=[verified_by])

class Notice(db.Model):
    __tablename__ = 'notice'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

# Add ExamSettings model after other models
class ExamSettings(db.Model):
    __tablename__ = 'exam_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    exam_name = db.Column(db.String(100), nullable=False)
    time_limit = db.Column(db.Integer, nullable=False)  # Time limit in minutes
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

# Create necessary directories
def create_upload_directories():
    directories = [
        os.path.join('static', 'uploads'),
        os.path.join('static', 'images'),
        os.path.join('static', 'marksheets')
    ]
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"Created directory: {directory}")
        except Exception as e:
            print(f"Error creating directory {directory}: {str(e)}")

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except:
        return None

def init_db():
    with app.app_context():
        # Only create tables if they don't exist
        db.create_all()
        
        # Create necessary directories
        create_upload_directories()
        
        # Create a default admin/teacher account if it doesn't exist
        default_teacher = User.query.filter_by(email='admin@example.com').first()
        if not default_teacher:
            default_teacher = User(
                full_name='Admin Teacher',
                email='admin@example.com',
                role='teacher',
                department='Administration'
            )
            default_teacher.set_password('admin123')
            
            try:
                db.session.add(default_teacher)
                db.session.commit()
                print("Default teacher account created successfully!")
            except Exception as e:
                db.session.rollback()
                print(f"Error creating default teacher: {str(e)}")
        
        print("Database initialized successfully!")

# Initialize database and create tables
with app.app_context():
    # Create tables without dropping existing ones
    db.create_all()
    create_upload_directories()
    
    # Check if we need to add new columns to the semester_results table
    inspector = inspect(db.engine)
    columns = [col['name'] for col in inspector.get_columns('semester_results')]
    
    # If verified column doesn't exist, add it and the other new columns
    if 'verified' not in columns:
        try:
            print("Adding verification columns to semester_results table...")
            with db.engine.connect() as conn:
                conn.execute(text('ALTER TABLE semester_results ADD COLUMN verified BOOLEAN DEFAULT 0'))
                conn.execute(text('ALTER TABLE semester_results ADD COLUMN verified_by INTEGER'))
                conn.execute(text('ALTER TABLE semester_results ADD COLUMN verified_at DATETIME'))
                conn.commit()
            print("Successfully added verification columns!")
        except Exception as e:
            print(f"Error adding verification columns: {str(e)}")
            # If the above fails, try another approach or inform user to recreate the database

# Call this function when the app starts
with app.app_context():
    # Create tables without dropping existing ones
    db.create_all()
    create_upload_directories()

# Route for home page (redirect to login)
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/logout', methods=['GET', 'POST'])
@login_required
@csrf.exempt  # Add CSRF exemption for logout
def logout():
    try:
        # Clear Flask-Login
        logout_user()
        
        # Clear session data
        session.clear()
        
        # Commit the session
        db.session.commit()
        
        flash('You have been logged out successfully.', 'info')
        return redirect(url_for('login'))
    except Exception as e:
        print(f"Error during logout: {str(e)}")
        flash('Error during logout. Please try again.', 'error')
        return redirect(url_for('login'))

# Registration route for Teacher
@app.route('/register_teacher', methods=['GET', 'POST'])
@csrf.exempt  # Add CSRF exemption for this route
def register_teacher():
    if request.method == 'POST':
        try:
            # Get form data with proper error handling
            full_name = request.form.get('full_name', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '').strip()
            department = request.form.get('department', '').strip()
            
            # Enhanced validation
            if not full_name or not email or not password or not department:
                flash('All fields are required', 'error')
                return render_template('register_teacher.html'), 400
            
            # Validate email format
            if '@' not in email:
                flash('Please enter a valid email address', 'error')
                return render_template('register_teacher.html'), 400
            
            # Check if user already exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('Email already registered', 'error')
                return render_template('register_teacher.html'), 400
            
            # Create new teacher user
            new_user = User(
                full_name=full_name,
                email=email,
                role='teacher',
                department=department
            )
            new_user.set_password(password)
            
            # Add and commit to database
            db.session.add(new_user)
            db.session.commit()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Registration error: {str(e)}")
            flash('Registration failed. Please try again.', 'error')
            return render_template('register_teacher.html'), 400
    
    # GET request - show registration form
    return render_template('register_teacher.html')

@app.route('/add_sports_event', methods=['GET', 'POST'])
@csrf.exempt
def add_sports_event():
    if 'user_id' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            # Get form data with proper error handling
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            event_date_str = request.form.get('event_date', '').strip()
            
            # Validate required fields
            if not title or not event_date_str:
                flash('Title and event date are required', 'error')
                events = SportsEvent.query.order_by(SportsEvent.event_date.desc()).all()
                return render_template('add_sports_event.html', events=events), 400
            
            try:
                event_date = datetime.strptime(event_date_str, '%Y-%m-%d').date()
            except ValueError:
                flash('Invalid date format. Please use YYYY-MM-DD', 'error')
                events = SportsEvent.query.order_by(SportsEvent.event_date.desc()).all()
                return render_template('add_sports_event.html', events=events), 400
            
            # Handle image upload
            image_path = None
            if 'event_image' in request.files:
                file = request.files['event_image']
                if file and file.filename != '':
                    if not allowed_file(file.filename):
                        flash('Invalid file type. Please upload PNG, JPG or JPEG images only.', 'error')
                        events = SportsEvent.query.order_by(SportsEvent.event_date.desc()).all()
                        return render_template('add_sports_event.html', events=events), 400
                        
                    filename = secure_filename(file.filename)
                    # Store in uploads directory
                    upload_folder = os.path.join('static', 'uploads')
                    os.makedirs(upload_folder, exist_ok=True)
                    file_path = os.path.join(upload_folder, filename)
                    file.save(file_path)
                    # Store relative path in database
                    image_path = os.path.join('uploads', filename).replace('\\', '/')

            # Create new event
            new_event = SportsEvent(
                title=title,
                description=description,
                event_date=event_date,
                image_path=image_path
            )
            db.session.add(new_event)
            db.session.commit()
            flash('Sports event added successfully!', 'success')
            return redirect(url_for('teacher_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Error adding sports event: {str(e)}")
            flash('Error adding sports event. Please try again.', 'error')
            events = SportsEvent.query.order_by(SportsEvent.event_date.desc()).all()
            return render_template('add_sports_event.html', events=events), 400

    # GET request
    events = SportsEvent.query.order_by(SportsEvent.event_date.desc()).all()
    return render_template('add_sports_event.html', events=events)

@app.route('/register_participant/<int:event_id>', methods=['POST'])
@csrf.exempt  # Using the correct decorator from csrf object
def register_participant(event_id):
    if 'user_id' not in session:
        flash('Please login to register for events', 'error')
        return redirect(url_for('login'))
    
    try:
        # Get current user
        user = User.query.get(session['user_id'])
        
        # Check if already registered
        existing = Participant.query.filter_by(
            event_id=event_id,
            name=user.full_name
        ).first()
        
        if existing:
            flash('You are already registered for this event!', 'warning')
            return redirect(url_for('student_dashboard'))
        
        # Create new participant
        new_participant = Participant(
            name=user.full_name,
            branch=user.branch,
            semester=user.semester,
            event_id=event_id
        )
        
        db.session.add(new_participant)
        db.session.commit()
        
        flash('Successfully registered for the event!', 'success')
        
    except Exception as e:
        db.session.rollback()
        print(f"Error registering for event: {str(e)}")
        flash('Error registering for the event. Please try again.', 'error')
    
    return redirect(url_for('student_dashboard'))

@app.route('/delete_participant/<int:event_id>/<int:participant_id>', methods=['POST'])
def delete_participant(event_id, participant_id):
    if 'user_id' not in session or session['role'] != 'teacher':
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        participant = Participant.query.filter_by(
            id=participant_id, 
            event_id=event_id
        ).first()
        
        if participant:
            db.session.delete(participant)
            db.session.commit()
            return jsonify({'message': 'Participant removed successfully'}), 200
        else:
            return jsonify({'error': 'Participant not found'}), 404
            
    except Exception as e:
        db.session.rollback()
        print(f"Error removing participant: {str(e)}")
        return jsonify({'error': 'Error removing participant'}), 500

@app.route('/event/<int:event_id>')
def event_details(event_id):
    event = SportsEvent.query.get_or_404(event_id)
    return render_template('event_details.html', event=event)

@app.route('/sports_events')
def sports_events():
    if 'user_id' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))
    
    # Get all sports events ordered by date
    events = SportsEvent.query.order_by(SportsEvent.event_date.desc()).all()
    return render_template('sports_events.html', events=events)

@app.route('/delete_sports_event/<int:event_id>', methods=['POST'])
@login_required
@teacher_required
@csrf.exempt
def delete_sports_event(event_id):
    try:
        event = SportsEvent.query.get_or_404(event_id)
        
        # First delete all participants related to this event
        Participant.query.filter_by(event_id=event_id).delete()
        
        # Delete the image file if it exists
        if event.image_path:
            try:
                file_path = os.path.join('static', event.image_path)
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception as e:
                print(f"Error deleting image file: {str(e)}")

        # Delete the event
        db.session.delete(event)
        db.session.commit()
        
        return jsonify({'message': 'Event deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting event: {str(e)}")
        return jsonify({'error': 'Error deleting event'}), 500

@app.route('/add_notice', methods=['GET', 'POST'])
@csrf.exempt  # Add CSRF exemption
def add_notice():
    if 'user_id' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        
        if not title or not content:
            flash('Both title and content are required.', 'error')
            return redirect(url_for('teacher_dashboard'))
            
        try:
            new_notice = Notice(
                title=title,
                content=content,
                author_id=session['user_id']
            )
            db.session.add(new_notice)
            db.session.commit()
            flash('Notice added successfully!', 'success')
            return redirect(url_for('teacher_dashboard'))
        except Exception as e:
            db.session.rollback()
            print(f"Error adding notice: {str(e)}")
            flash('Error adding notice. Please try again.', 'error')
            return redirect(url_for('teacher_dashboard'))

    return redirect(url_for('teacher_dashboard'))

@app.route('/delete_account', methods=['POST'])
def delete_account():
    # Assuming the user is logged in and their ID is stored in the session
    if 'user_id' not in session:
        flash('You need to be logged in to delete your account.', 'danger')
        return redirect(url_for('login'))  # Redirect to login page if not logged in

    user_id = session['user_id']
    user = User.query.get(user_id)

    if user:
        db.session.delete(user)
        db.session.commit()

        flash('Your account has been deleted successfully.', 'success')

        # Log the user out after account deletion
        session.pop('user_id', None)  # Remove the user ID from session

        return redirect(url_for('home'))  # Redirect to home page or login page after deletion
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('home'))  # If no user found, redirect to home

# Registration route for Student
@app.route('/register_student', methods=['GET', 'POST'])
def register_student():
    if request.method == 'POST':
        try:
            # Get form data
            full_name = request.form.get('full_name')
            email = request.form.get('email')
            password = request.form.get('password')
            branch = request.form.get('branch')
            semester = request.form.get('semester')
            
            # Validate required fields
            if not all([full_name, email, password, branch, semester]):
                flash('All fields are required', 'error')
                return redirect(url_for('register_student'))
            
            # Check if user already exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('Email already registered', 'error')
                return redirect(url_for('register_student'))
            
            # Create new student user
            new_user = User(
                full_name=full_name,
                email=email,
                role='student',
                branch=branch,
                semester=semester
            )
            new_user.set_password(password)
            
            # Add and commit to database
            db.session.add(new_user)
            db.session.commit()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Registration error: {str(e)}")
            flash('Registration failed. Please try again.', 'error')
            return redirect(url_for('register_student'))
    
    return render_template('register_student.html')

# Route to delete a question
@app.route('/delete_question/<int:question_id>', methods=['POST'])
@csrf.exempt
def delete_question(question_id):
    if 'user_id' not in session or session['role'] != 'teacher':
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        question = Question.query.get_or_404(question_id)
        db.session.delete(question)
        db.session.commit()
        flash('Question deleted successfully!', 'success')
        return jsonify({'success': True}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting question: {str(e)}")
        return jsonify({'error': 'Failed to delete question'}), 500

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Check if user is already logged in
    if current_user.is_authenticated:
        if current_user.role == 'teacher':
            return redirect(url_for('teacher_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        remember = True  # Always remember the user

        if not all([email, password, role]):
            flash('Please fill in all fields', 'error')
            return redirect(url_for('login'))

        try:
            user = User.query.filter_by(email=email).first()
            
            if user and user.check_password(password):
                if user.role != role:
                    flash('Invalid role selected', 'error')
                    return redirect(url_for('login'))
                
                # Log in the user with Flask-Login
                login_user(user, remember=remember)
                
                # Make session permanent
                session.permanent = True
                
                # Store additional info in session
                session['role'] = user.role
                session['name'] = user.full_name
                session['user_id'] = user.id
                
                # Commit the session
                db.session.commit()
                
                flash(f'Welcome back, {user.full_name}!', 'success')
                
                # Get the next page from args or use default
                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                    
                if role == 'teacher':
                    return redirect(url_for('teacher_dashboard'))
                else:
                    return redirect(url_for('student_dashboard'))
            else:
                flash('Invalid email or password', 'error')
                return redirect(url_for('login'))
                
        except Exception as e:
            print(f"Login error: {str(e)}")
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('login'))
    
    # GET request - show login page
    return render_template('login.html')

@app.route('/upload_marksheet/<int:score_id>', methods=['GET', 'POST'])
def upload_marksheet(score_id):
    if 'user_id' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))
    
    score_entry = ExamScore.query.get_or_404(score_id)
    
    if request.method == 'POST':
        file = request.files['marksheet']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            score_entry.marksheet_image = filepath  # Save the filepath in the database
            db.session.commit()
            flash('Marksheet uploaded successfully!', 'success')
            return redirect(url_for('teacher_dashboard'))
        else:
            flash('Invalid file format. Please upload an image or PDF.', 'error')
    
    return render_template('upload_marksheet.html', score=score_entry)

@app.route('/view_marksheet/<int:score_id>')
def view_marksheet(score_id):
    # Fetch the exam score entry to get the marksheet path or filename
    score = ExamScore.query.get(score_id)
    
    if score and score.marksheet_image:
        # Assuming the marksheet filename is stored in the database
        marksheet_image = score.marksheet_image
        filepath = os.path.join('', marksheet_image)  # Adjust path
        return send_file(filepath, as_attachment=True)  # Sends the image to the browser
    else:
        flash('Marksheets not available.', 'error')
        return redirect(url_for('student_dashboard'))

@app.route('/teacher_dashboard')
@login_required
@teacher_required
def teacher_dashboard():
    try:
        print("Loading teacher dashboard data...")
        
        # Get all students with better error handling
        try:
            students = User.query.filter_by(role='student').order_by(User.created_at.desc()).all()
            print(f"Loaded {len(students)} students")
        except Exception as e:
            print(f"Error loading students: {str(e)}")
            students = []
        
        # Get existing questions with better error handling
        try:
            questions = Question.query.all()
            print(f"Loaded {len(questions)} questions")
        except Exception as e:
            print(f"Error loading questions: {str(e)}")
            questions = []
        
        # Get student scores with better error handling
        try:
            student_scores = ExamScore.query.order_by(ExamScore.created_at.desc()).all()
            print(f"Loaded {len(student_scores)} student scores")
        except Exception as e:
            print(f"Error loading student scores: {str(e)}")
            student_scores = []
        
        # Get events with better error handling
        try:
            events = SportsEvent.query.order_by(SportsEvent.event_date.desc()).all()
            print(f"Loaded {len(events)} events")
        except Exception as e:
            print(f"Error loading events: {str(e)}")
            events = []
        
        # Get notices with better error handling
        try:
            notices = Notice.query.order_by(Notice.created_at.desc()).all()
            print(f"Loaded {len(notices)} notices")
        except Exception as e:
            print(f"Error loading notices: {str(e)}")
            notices = []
        
        # Count active events (events with future dates)
        active_events = 0
        today = datetime.now().date()
        for event in events:
            if event.event_date.date() >= today:
                active_events += 1
        
        # Calculate totals for dashboard stats
        total_questions = len(questions)
        total_students = len(students)
        
        print(f"Teacher dashboard loaded successfully with: {total_questions} questions, {total_students} students, {active_events} active events")
        
        return render_template('teacher_dashboard.html',
                             questions=questions,
                             student_scores=student_scores,
                             events=events,
                             notices=notices,
                             students=students,
                             active_events=active_events,
                             total_questions=total_questions,
                             total_students=total_students)
                             
    except Exception as e:
        print(f"Error loading teacher dashboard: {str(e)}")
        flash('Error loading dashboard', 'error')
        return redirect(url_for('login'))

@app.route('/delete_notice/<int:notice_id>', methods=['POST'])
@login_required
@teacher_required
@csrf.exempt
def delete_notice(notice_id):
    try:
        # Fetch the notice from the database using notice_id
        notice = Notice.query.get_or_404(notice_id)
        
        # Delete the notice
        db.session.delete(notice)
        db.session.commit()
        
        # Return JSON response for AJAX request
        return jsonify({'success': True, 'message': 'Notice deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting notice: {str(e)}")
        return jsonify({'success': False, 'error': 'Error deleting notice'}), 400

@app.route('/manage_sports_events')
def manage_sports_events():
    sports_events = SportsEvent.query.all()  # Get all sports events
    return render_template('dashboard.html', sports_events=sports_events)

def get_questions_from_database():
    return Question.query.all()

def get_questions():
    return Question.query.all() 

def get_score_by_student_id(student_id):
    # Query the ExamScore table for the specific student_id
    return ExamScore.query.filter_by(student_id=student_id).first()

@app.route('/student_dashboard')
@login_required
@student_required
def student_dashboard():
    try:
        # Get current user
        user = current_user
        
        # Get all events
        events = SportsEvent.query.order_by(SportsEvent.event_date.desc()).all()
        
        # Get list of events this student has registered for
        registered_events = set()
        user_registrations = Participant.query.filter_by(name=user.full_name).all()
        for registration in user_registrations:
            registered_events.add(registration.event_id)
        
        # Get student's exam scores
        student_scores = ExamScore.query.filter_by(student_id=user.id)\
            .order_by(ExamScore.created_at.desc())\
            .all()
        
        # Get questions for exam
        questions = Question.query.all()
        
        # Get notices
        notices = Notice.query.order_by(Notice.created_at.desc()).all()
        
        return render_template('student_dashboard.html', 
                             events=events,
                             registered_events=registered_events,
                             user=user,
                             student_scores=student_scores,
                             questions=questions,
                             notices=notices)
                             
    except Exception as e:
        print(f"Error loading student dashboard: {str(e)}")
        flash('Error loading dashboard', 'error')
        return redirect(url_for('login'))

@app.route('/give_exam')
@login_required
@student_required
@csrf.exempt
def give_exam():
    try:
        # Get all questions first
        all_questions = Question.query.all()
        if not all_questions:
            flash('No questions available at the moment.', 'info')
            return redirect(url_for('student_dashboard'))

        # Get active exam settings or use default values
        active_setting = ExamSettings.query.filter_by(is_active=True).first()
        exam_name = active_setting.exam_name if active_setting else "General Knowledge Exam"
        
        # Check if student has already taken this exam
        existing_score = ExamScore.query.filter_by(
            student_id=current_user.id,
            subject=exam_name
        ).first()
        
        if existing_score:
            flash(f'You have already taken the {exam_name}. You cannot retake this exam.', 'warning')
            return redirect(url_for('student_dashboard'))

        # Get exam time limit from settings or use default
        exam_time_limit = active_setting.time_limit if active_setting else 60
        
        # Clear any existing exam session data
        if 'exam_start_time' in session:
            session.pop('exam_start_time', None)
        if 'exam_time_limit' in session:
            session.pop('exam_time_limit', None)
            
        # Store exam start time and settings in session
        session['exam_start_time'] = datetime.utcnow().timestamp()
        session['exam_time_limit'] = exam_time_limit
        session['exam_name'] = exam_name
        
        # Log exam start
        print(f"Started exam session for user {current_user.id} ({current_user.full_name})")
        print(f"Exam: {exam_name}, Time limit={exam_time_limit} minutes, Questions={len(all_questions)}")
        
        return render_template('give_exam.html', 
                             questions=all_questions,
                             time_limit_minutes=exam_time_limit,
                             exam_name=exam_name)
        
    except Exception as e:
        print(f"Error loading exam: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('Error loading exam. Please try again.', 'error')
        return redirect(url_for('student_dashboard'))

@app.route('/submit_exam', methods=['POST'])
@login_required
@student_required
@csrf.exempt
def submit_exam():
    try:
        # Validate exam session
        if 'exam_start_time' not in session or 'exam_time_limit' not in session or 'exam_name' not in session:
            flash('Invalid exam session. Please start a new exam.', 'info')
            return redirect(url_for('give_exam'))
            
        # Check time limit
        current_time = datetime.utcnow().timestamp()
        time_elapsed = current_time - session['exam_start_time']
        time_limit = session['exam_time_limit'] * 60  # Convert minutes to seconds
        
        if time_elapsed > time_limit:
            flash('Exam time limit exceeded. Your answers were automatically submitted.', 'warning')
        
        exam_name = session['exam_name']
        
        # Process answers
        answers = {}
        score = 0
        total_questions = 0
        
        print("Processing exam submission...")
        print("Form data received:", dict(request.form))
        
        # Process submitted answers
        for key, value in request.form.items():
            if key.startswith('question_'):
                try:
                    question_id = int(key.split('_')[1])
                    answers[question_id] = value
                    total_questions += 1
                except (ValueError, IndexError) as e:
                    print(f"Error parsing question ID from '{key}': {str(e)}")
        
        print(f"Processing {total_questions} answers: {answers}")
        
        if not answers:
            flash('No answers were submitted. Please try again.', 'warning')
            return redirect(url_for('give_exam'))
        
        # Calculate score
        for question_id, submitted_answer in answers.items():
            try:
                question = Question.query.get(question_id)
                if not question:
                    print(f"Question {question_id} not found in database")
                    continue
                    
                submitted_value = getattr(question, submitted_answer, None)
                
                print(f"Question {question_id}: '{question.question_text}'")
                print(f"Submitted: '{submitted_answer}' -> '{submitted_value}'")
                print(f"Correct: '{question.correct_answer}'")
                
                if submitted_value == question.correct_answer:
                    score += 1
                    print(f"CORRECT! Score: {score}")
                else:
                    print(f"INCORRECT. Score: {score}")
            except Exception as e:
                print(f"Error processing question {question_id}: {str(e)}")
        
        # Calculate percentage
        percentage = (score / total_questions) * 100 if total_questions > 0 else 0
        
        # Save exam score
        try:
            new_score = ExamScore(
                student_id=current_user.id,
                subject=exam_name,
                marks=score,
                max_marks=total_questions,
                exam_date=datetime.utcnow(),
                questions_attempted=','.join(str(qid) for qid in answers.keys())
            )
            
            db.session.add(new_score)
            db.session.commit()
            print(f"Exam score saved: {score}/{total_questions} ({percentage:.1f}%)")
            
            # Clear exam session data
            session.pop('exam_start_time', None)
            session.pop('exam_time_limit', None)
            session.pop('exam_name', None)
            
            flash(f'Exam submitted successfully! Your score: {score}/{total_questions} ({percentage:.1f}%)', 'success')
            
        except Exception as e:
            db.session.rollback()
            print(f"Error saving exam score: {str(e)}")
            flash('Error saving your exam score. Please contact support.', 'error')
            
        return redirect(url_for('student_dashboard'))
        
    except Exception as e:
        db.session.rollback()
        print(f"Error submitting exam: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('Error submitting exam. Please try again.', 'error')
        return redirect(url_for('give_exam'))

@app.route('/add_question', methods=['GET', 'POST'])
@login_required
@teacher_required
@csrf.exempt  # Add CSRF exemption
def add_question():
    if request.method == 'POST':
        try:
            # Get form data with proper error handling
            question_text = request.form.get('question_text', '').strip()
            option1 = request.form.get('option1', '').strip()
            option2 = request.form.get('option2', '').strip()
            option3 = request.form.get('option3', '').strip()
            option4 = request.form.get('option4', '').strip()
            correct_answer = request.form.get('correct_answer', '').strip()
            time_limit = request.form.get('time_limit', type=int, default=30)  # Default 30 seconds per question
            exam_time_limit = request.form.get('exam_time_limit', type=int, default=60)
            
            # Enhanced debug print
            print(f"Adding question: '{question_text}'")
            print(f"Options: 1='{option1}', 2='{option2}', 3='{option3}', 4='{option4}'")
            print(f"Correct answer selection: '{correct_answer}'")
            print(f"Time limit: {time_limit}s, Exam time limit: {exam_time_limit}m")
            
            # Validate all fields are present
            if not all([question_text, option1, option2, option3, option4, correct_answer]):
                missing = []
                if not question_text: missing.append("question text")
                if not option1: missing.append("option 1")
                if not option2: missing.append("option 2")
                if not option3: missing.append("option 3")
                if not option4: missing.append("option 4")
                if not correct_answer: missing.append("correct answer")
                flash(f'Missing required fields: {", ".join(missing)}', 'error')
                return render_template('add_question.html')
            
            # Validate time limits
            if time_limit < 1 or time_limit > 120:
                flash('Time limit per question must be between 1 and 120 seconds', 'error')
                return render_template('add_question.html')
                
            # Validate exam time limit
            if exam_time_limit < 1 or exam_time_limit > 180:
                flash('Exam time limit must be between 1 and 180 minutes', 'error')
                return render_template('add_question.html')
            
            # Create new question - store the correct answer as the actual option text
            # This way, when comparing in submit_exam, we can directly compare the text values
            if correct_answer == 'option1':
                correct_answer_text = option1
            elif correct_answer == 'option2':
                correct_answer_text = option2
            elif correct_answer == 'option3':
                correct_answer_text = option3
            elif correct_answer == 'option4':
                correct_answer_text = option4
            else:
                flash(f'Invalid correct answer selection: {correct_answer}', 'error')
                return render_template('add_question.html')
            
            print(f"Correct answer text: '{correct_answer_text}'")
            
            # Create new question
            new_question = Question(
                question_text=question_text,
                option1=option1,
                option2=option2,
                option3=option3,
                option4=option4,
                correct_answer=correct_answer_text,  # Store the actual text of the correct answer
                time_limit=time_limit,
                exam_time_limit=exam_time_limit
            )
            
            db.session.add(new_question)
            db.session.commit()
            
            print(f"Question added successfully with ID: {new_question.id}")
            
            flash('Question added successfully!', 'success')
            return redirect(url_for('teacher_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Error adding question: {str(e)}")
            import traceback
            traceback.print_exc()  # Print full stack trace for debugging
            flash('Error adding question. Please try again.', 'error')
            return render_template('add_question.html')
    
    # GET request
    return render_template('add_question.html')

# Edit question route (for teachers to edit questions)
@app.route('/edit_question/<int:question_id>', methods=['GET', 'POST'])
@login_required
@teacher_required
@csrf.exempt  # Add CSRF exemption
def edit_question(question_id):
    try:
        question = Question.query.get_or_404(question_id)
        
        if request.method == 'POST':
            try:
                # Get form data with proper error handling
                question_text = request.form.get('question_text', '').strip()
                option1 = request.form.get('option1', '').strip()
                option2 = request.form.get('option2', '').strip()
                option3 = request.form.get('option3', '').strip()
                option4 = request.form.get('option4', '').strip()
                correct_answer = request.form.get('correct_answer', '').strip()
                time_limit = request.form.get('time_limit', type=int, default=30)
                exam_time_limit = request.form.get('exam_time_limit', type=int, default=60)
                
                # Debug info
                print(f"Editing question ID {question_id}: '{question_text}'")
                print(f"Options: 1='{option1}', 2='{option2}', 3='{option3}', 4='{option4}'")
                print(f"Selected correct answer: '{correct_answer}'")
                print(f"Time limits: {time_limit}s per question, {exam_time_limit}m for exam")
    
                # Validate all fields are present
                if not all([question_text, option1, option2, option3, option4, correct_answer]):
                    missing = []
                    if not question_text: missing.append("question text")
                    if not option1: missing.append("option 1")
                    if not option2: missing.append("option 2")
                    if not option3: missing.append("option 3")
                    if not option4: missing.append("option 4")
                    if not correct_answer: missing.append("correct answer")
                    flash(f'Missing required fields: {", ".join(missing)}', 'error')
                    return render_template('edit_question.html', question=question, correct_option=correct_answer), 400
    
                # Validate correct_answer is one of the valid options
                if correct_answer not in ['option1', 'option2', 'option3', 'option4']:
                    flash(f'Invalid correct answer selection: {correct_answer}', 'error')
                    return render_template('edit_question.html', question=question, correct_option=correct_answer), 400
    
                # Map the selected option to its text value
                if correct_answer == 'option1':
                    correct_answer_text = option1
                elif correct_answer == 'option2':
                    correct_answer_text = option2
                elif correct_answer == 'option3':
                    correct_answer_text = option3
                elif correct_answer == 'option4':
                    correct_answer_text = option4
                else:
                    flash(f'Invalid correct answer selection: {correct_answer}', 'error')
                    return render_template('edit_question.html', question=question, correct_option=correct_answer), 400
                
                print(f"Correct answer text: '{correct_answer_text}'")
    
                # Update the question
                question.question_text = question_text
                question.option1 = option1
                question.option2 = option2
                question.option3 = option3
                question.option4 = option4
                question.correct_answer = correct_answer_text
                question.time_limit = time_limit
                question.exam_time_limit = exam_time_limit
    
                db.session.commit()
                print(f"Question ID {question_id} updated successfully")
                flash('Question updated successfully!', 'success')
                return redirect(url_for('teacher_dashboard'))
    
            except Exception as e:
                db.session.rollback()
                print(f"Error updating question: {str(e)}")
                import traceback
                traceback.print_exc()  # Print full stack trace for debugging
                flash('Error updating question. Please try again.', 'error')
                return render_template('edit_question.html', question=question, correct_option=correct_answer), 400
    
        # For GET request, determine which option contains the correct answer
        correct_option = None
        if question.correct_answer == question.option1:
            correct_option = "option1"
        elif question.correct_answer == question.option2:
            correct_option = "option2"
        elif question.correct_answer == question.option3:
            correct_option = "option3"
        elif question.correct_answer == question.option4:
            correct_option = "option4"
        else:
            # If no match found, default to option1 and log the issue
            print(f"WARNING: Question {question_id} has correct_answer '{question.correct_answer}' which doesn't match any option")
            correct_option = "option1"
        
        # Pass the correct_option to the template
        return render_template('edit_question.html', question=question, correct_option=correct_option)
        
    except Exception as e:
        print(f"Error accessing question {question_id}: {str(e)}")
        flash('Error retrieving question. Please try again.', 'error')
        return redirect(url_for('teacher_dashboard'))

# Route to delete student exam score
@app.route('/delete_score/<int:score_id>', methods=['POST'])
@csrf.exempt  # Add CSRF exemption
def delete_score(score_id):
    if 'user_id' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))

    try:
        # Fetch the score entry to delete
        score_to_delete = ExamScore.query.get_or_404(score_id)

        # Delete the score entry
        db.session.delete(score_to_delete)
        db.session.commit()
        flash('Score deleted successfully!', 'success')
        return redirect(url_for('teacher_dashboard'))
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting score: {str(e)}")
        flash('Error deleting score. Please try again.', 'error')
        return redirect(url_for('teacher_dashboard'))

@app.route('/upload_semester_result', methods=['GET', 'POST'])
@login_required
@teacher_required
@csrf.exempt
def upload_semester_result():
    if request.method == 'POST':
        try:
            # Create directories if they don't exist
            create_upload_directories()
            
            student_id = request.form.get('student_id')
            semester = request.form.get('semester')
            marks = float(request.form.get('marks'))
            max_marks = float(request.form.get('max_marks'))
            result_date = datetime.strptime(request.form.get('result_date'), '%Y-%m-%d')
            
            # Calculate grade based on percentage
            percentage = (marks / max_marks) * 100
            grade = 'A+' if percentage >= 90 else 'A' if percentage >= 80 else 'B+' if percentage >= 70 else 'B' if percentage >= 60 else 'C'
            
            # Handle file upload
            marksheet_file = request.files.get('marksheet_file')
            marksheet_filename = None
            
            if marksheet_file and marksheet_file.filename:
                if allowed_file(marksheet_file.filename):
                    try:
                        # Generate unique filename
                        filename = secure_filename(marksheet_file.filename)
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        # Always use forward slashes for paths
                        marksheet_filename = f"marksheets/{timestamp}_{filename}"
                        
                        # Save the file using forward slashes
                        file_path = os.path.join('static', marksheet_filename)
                        os.makedirs(os.path.dirname(file_path), exist_ok=True)
                        # Convert Windows path to forward slashes before saving
                        file_path = file_path.replace('\\', '/')
                        marksheet_file.save(file_path)
                        print(f"Successfully saved marksheet file to: {file_path}")
                    except Exception as e:
                        print(f"Error saving marksheet file: {str(e)}")
                        flash('Error uploading marksheet file. Please try again.', 'error')
                        return redirect(url_for('upload_semester_result'))
                else:
                    flash('Invalid file type. Allowed types are: PDF, JPG, JPEG, PNG', 'error')
                    return redirect(url_for('upload_semester_result'))
            
            # Create new semester result with default subject value
            new_result = SemesterResult(
                student_id=student_id,
                semester=semester,
                subject='Semester Result',  # Default subject value
                marks=marks,
                max_marks=max_marks,
                grade=grade,
                result_date=result_date,
                created_by=current_user.id,
                marksheet_file=marksheet_filename,  # This will now have forward slashes
                verified=False,  # New field to indicate verification status
                verified_by=None,  # Teacher who verified
                verified_at=None  # When it was verified
            )
            
            db.session.add(new_result)
            db.session.commit()
            
            flash('Semester result uploaded successfully!', 'success')
            return redirect(url_for('view_semester_results'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Error uploading semester result: {str(e)}")
            flash('Error uploading result. Please try again.', 'error')
            return redirect(url_for('upload_semester_result'))
    
    # GET request - show upload form
    students = User.query.filter_by(role='student').all()
    return render_template('upload_semester_result.html', students=students)

@app.route('/view_semester_results')
@login_required
def view_semester_results():
    try:
        if current_user.role == 'teacher':
            # Teachers can see all results
            results = SemesterResult.query.order_by(
                SemesterResult.semester.desc(),
                SemesterResult.result_date.desc()
            ).all()
        else:
            # Students can only see their own results
            results = SemesterResult.query.filter_by(student_id=current_user.id).order_by(
                SemesterResult.semester.desc(),
                SemesterResult.result_date.desc()
            ).all()
        
        return render_template('view_semester_results.html', results=results)
    except Exception as e:
        print(f"Error viewing semester results: {str(e)}")
        flash('Error loading results', 'error')
        return redirect(url_for('student_dashboard' if current_user.role == 'student' else 'teacher_dashboard'))

@app.route('/delete_semester_result/<int:result_id>', methods=['POST'])
@login_required
@teacher_required
@csrf.exempt
def delete_semester_result(result_id):
    try:
        result = SemesterResult.query.get_or_404(result_id)
        
        # Delete associated marksheet file if it exists
        if result.marksheet_file:
            file_path = os.path.join('static', result.marksheet_file)
            if os.path.exists(file_path):
                os.remove(file_path)
        
        db.session.delete(result)
        db.session.commit()
        
        flash('Semester result deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting semester result: {str(e)}")
        flash('Error deleting result', 'error')
    
    return redirect(url_for('view_semester_results'))

@app.route('/view_student_details/<int:student_id>')
def view_student_details(student_id):
    if 'user_id' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))
        
    student = User.query.get_or_404(student_id)
    scores = ExamScore.query.filter_by(student_id=student_id).order_by(ExamScore.id.desc()).all()
    
    return render_template('student_details.html', student=student, scores=scores)

@app.route('/delete_student/<int:student_id>', methods=['POST'])
@csrf.exempt
def delete_student(student_id):
    if 'user_id' not in session or session['role'] != 'teacher':
        return jsonify({'error': 'Unauthorized'}), 401
        
    try:
        student = User.query.get_or_404(student_id)
        
        # Check if the user is actually a student
        if student.role != 'student':
            return jsonify({'error': 'Can only delete student accounts'}), 400
            
        # Delete related records first
        ExamScore.query.filter_by(student_id=student_id).delete()
        Participant.query.filter_by(name=student.full_name).delete()
        
        # Delete the student
        db.session.delete(student)
        db.session.commit()
        
        flash('Student account deleted successfully!', 'success')
        return jsonify({'success': True}), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting student: {str(e)}")
        return jsonify({'error': 'Failed to delete student account'}), 500

# Add route for managing exam settings
@app.route('/manage_exam_settings', methods=['GET', 'POST'])
@login_required
@teacher_required
@csrf.exempt  # Add CSRF exemption
def manage_exam_settings():
    if request.method == 'POST':
        try:
            exam_name = request.form.get('exam_name', '').strip()
            time_limit = request.form.get('time_limit', type=int)
            
            if not exam_name or not time_limit:
                flash('Exam name and time limit are required', 'error')
                exam_settings = ExamSettings.query.order_by(ExamSettings.created_at.desc()).all()
                return render_template('manage_exam_settings.html', exam_settings=exam_settings)
            
            if time_limit < 1 or time_limit > 180:
                flash('Time limit must be between 1 and 180 minutes', 'error')
                exam_settings = ExamSettings.query.order_by(ExamSettings.created_at.desc()).all()
                return render_template('manage_exam_settings.html', exam_settings=exam_settings)
            
            # Create new exam settings
            new_settings = ExamSettings(
                exam_name=exam_name,
                time_limit=time_limit,
                created_by=current_user.id  # Use current_user instead of session
            )
            
            # Deactivate all other exam settings
            ExamSettings.query.filter_by(is_active=True).update({'is_active': False})
            
            db.session.add(new_settings)
            db.session.commit()
            
            flash('Exam settings updated successfully!', 'success')
            return redirect(url_for('teacher_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Error updating exam settings: {str(e)}")
            flash('Error updating exam settings. Please try again.', 'error')
            exam_settings = ExamSettings.query.order_by(ExamSettings.created_at.desc()).all()
            return render_template('manage_exam_settings.html', exam_settings=exam_settings)
    
    # GET request - show current settings
    exam_settings = ExamSettings.query.order_by(ExamSettings.created_at.desc()).all()
    return render_template('manage_exam_settings.html', exam_settings=exam_settings)

@app.route('/toggle_exam_setting/<int:setting_id>', methods=['POST'])
@csrf.exempt
def toggle_exam_setting(setting_id):
    if 'user_id' not in session or session['role'] != 'teacher':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        setting = ExamSettings.query.get_or_404(setting_id)
        
        # Deactivate all settings first
        ExamSettings.query.filter_by(is_active=True).update({'is_active': False})
        
        # Activate the selected setting
        setting.is_active = True
        db.session.commit()
        
        return jsonify({'success': True}), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error toggling exam setting: {str(e)}")
        return jsonify({'error': 'Failed to update exam setting'}), 500

@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files with proper path handling"""
    # URL decode the filename first (handles %5C and other encoded characters)
    filename = unquote(filename)
    # Normalize path by replacing backslashes with forward slashes
    filename = filename.replace('\\', '/').lstrip('/')
    return send_from_directory('static', filename)

@app.route('/upload_student_marksheet/<int:result_id>', methods=['GET', 'POST'])
@login_required
@student_required
@csrf.exempt
def upload_student_marksheet(result_id):
    try:
        # Get the result record and verify it belongs to the current student
        result = SemesterResult.query.get_or_404(result_id)
        
        if result.student_id != current_user.id:
            flash('Access denied. You can only upload marksheets for your own results.', 'error')
            return redirect(url_for('view_semester_results'))
        
        if request.method == 'POST':
            # Create directories if they don't exist
            create_upload_directories()
            
            # Handle file upload
            marksheet_file = request.files.get('marksheet_file')
            
            if not marksheet_file or not marksheet_file.filename:
                flash('No file selected. Please select a file to upload.', 'error')
                return redirect(url_for('upload_student_marksheet', result_id=result_id))
            
            if not allowed_file(marksheet_file.filename):
                flash('Invalid file type. Allowed types are: PDF, JPG, JPEG, PNG', 'error')
                return redirect(url_for('upload_student_marksheet', result_id=result_id))
            
            try:
                # Generate unique filename
                filename = secure_filename(marksheet_file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                marksheet_filename = f"marksheets/student_{current_user.id}_{timestamp}_{filename}"
                
                # Save the file using forward slashes
                file_path = os.path.join('static', marksheet_filename)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                file_path = file_path.replace('\\', '/')
                marksheet_file.save(file_path)
                
                # Update the marksheet_file path in the database
                result.marksheet_file = marksheet_filename
                db.session.commit()
                
                flash('Your marksheet has been uploaded successfully!', 'success')
                return redirect(url_for('view_semester_results'))
                
            except Exception as e:
                print(f"Error saving marksheet file: {str(e)}")
                flash('Error uploading marksheet file. Please try again.', 'error')
                return redirect(url_for('upload_student_marksheet', result_id=result_id))
        
        # GET request - show upload form
        return render_template('upload_student_marksheet.html', result=result)
        
    except Exception as e:
        print(f"Error in upload_student_marksheet: {str(e)}")
        flash('Error processing your request. Please try again.', 'error')
        return redirect(url_for('view_semester_results'))

@app.route('/add_student_result', methods=['GET', 'POST'])
@login_required
@student_required
@csrf.exempt
def add_student_result():
    try:
        if request.method == 'POST':
            # Create directories if they don't exist
            create_upload_directories()
            
            # Get form data
            semester = request.form.get('semester')
            subject = request.form.get('subject', '').strip()
            marks = float(request.form.get('marks'))
            max_marks = float(request.form.get('max_marks'))
            result_date_str = request.form.get('result_date')
            
            # Validate input data
            if not all([semester, subject, result_date_str]) or marks < 0 or max_marks <= 0:
                flash('Please fill all required fields with valid values', 'error')
                return redirect(url_for('add_student_result'))
                
            # Parse date
            try:
                result_date = datetime.strptime(result_date_str, '%Y-%m-%d')
            except ValueError:
                flash('Invalid date format. Please use YYYY-MM-DD format.', 'error')
                return redirect(url_for('add_student_result'))
                
            # Calculate grade based on percentage
            percentage = (marks / max_marks) * 100
            grade = 'A+' if percentage >= 90 else 'A' if percentage >= 80 else 'B+' if percentage >= 70 else 'B' if percentage >= 60 else 'C'
            
            # Handle file upload
            marksheet_file = request.files.get('marksheet_file')
            marksheet_filename = None
            
            if marksheet_file and marksheet_file.filename:
                if allowed_file(marksheet_file.filename):
                    try:
                        # Generate unique filename
                        filename = secure_filename(marksheet_file.filename)
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        # Always use forward slashes for paths
                        marksheet_filename = f"marksheets/student_{current_user.id}_{timestamp}_{filename}"
                        
                        # Save the file using forward slashes
                        file_path = os.path.join('static', marksheet_filename)
                        os.makedirs(os.path.dirname(file_path), exist_ok=True)
                        # Convert Windows path to forward slashes before saving
                        file_path = file_path.replace('\\', '/')
                        marksheet_file.save(file_path)
                        print(f"Successfully saved marksheet file to: {file_path}")
                    except Exception as e:
                        print(f"Error saving marksheet file: {str(e)}")
                        flash('Error uploading marksheet file. Please try again.', 'error')
                        return redirect(url_for('add_student_result'))
                else:
                    flash('Invalid file type. Allowed types are: PDF, JPG, JPEG, PNG', 'error')
                    return redirect(url_for('add_student_result'))
            
            # Create new semester result
            new_result = SemesterResult(
                student_id=current_user.id,  # Current student's ID
                semester=semester,
                subject=subject,
                marks=marks,
                max_marks=max_marks,
                grade=grade,
                result_date=result_date,
                created_by=current_user.id,  # Student is creating this result
                marksheet_file=marksheet_filename,
                verified=False,  # New field to indicate verification status
                verified_by=None,  # Teacher who verified
                verified_at=None  # When it was verified
            )
            
            db.session.add(new_result)
            db.session.commit()
            
            flash('Your semester result has been added successfully!', 'success')
            return redirect(url_for('view_semester_results'))
            
        # GET request - show form
        return render_template('add_student_result.html')
        
    except Exception as e:
        db.session.rollback()
        print(f"Error adding student result: {str(e)}")
        flash('Error adding semester result. Please try again.', 'error')
        return redirect(url_for('student_dashboard'))

@app.route('/verify_result/<int:result_id>', methods=['POST'])
@login_required
@teacher_required
@csrf.exempt
def verify_result(result_id):
    try:
        # Get the result
        result = SemesterResult.query.get_or_404(result_id)
        
        # Update verification status
        result.verified = True
        result.verified_by = current_user.id
        result.verified_at = datetime.utcnow()
        
        db.session.commit()
        
        flash('Result has been verified successfully!', 'success')
        return redirect(url_for('view_semester_results'))
        
    except Exception as e:
        db.session.rollback()
        print(f"Error verifying result: {str(e)}")
        flash('Error verifying result. Please try again.', 'error')
        return redirect(url_for('view_semester_results'))

if __name__ == '__main__':
    init_db()  # Initialize database before running the app
    app.run(debug=True, port=8000)
