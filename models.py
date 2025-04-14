# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'teacher' or 'student'

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(100), nullable=False)
    option_b = db.Column(db.String(100), nullable=False)
    option_c = db.Column(db.String(100), nullable=False)
    option_d = db.Column(db.String(100), nullable=False)
    correct_answer = db.Column(db.String(1), nullable=False)  # A, B, C, or D
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'))

class Exam(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    questions = db.relationship('Question', backref='exam', lazy=True)

class ExamScore(db.Model):
    __tablename__ = 'exam_scores'
    
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    date_taken = db.Column(db.DateTime, default=datetime.utcnow)

    # Define the relationship
    student = db.relationship('User', backref='exam_scores')

    def __init__(self, student_id, score):
        self.student_id = student_id
        self.score = score

class SportsEvent(db.Model):
    __tablename__ = 'sports_events'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    event_date = db.Column(db.Date, nullable=False)
    image_path = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Participant(db.Model):
    __tablename__ = 'participants'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=True)
    gender = db.Column(db.String(10), nullable=True)
    contact_number = db.Column(db.String(15), nullable=True)
    branch = db.Column(db.String(50), nullable=False)
    semester = db.Column(db.String(20), nullable=False)
    registration_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    event_id = db.Column(db.Integer, db.ForeignKey('sports_events.id'), nullable=False)
    event = db.relationship('SportsEvent', backref=db.backref('participants', lazy=True))
