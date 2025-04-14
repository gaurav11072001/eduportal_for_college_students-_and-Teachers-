# create_teacher_user.py
from app import app, db, bcrypt
from models import User


# Teacher credentials
username = "teacher1"
password = "password123"

with app.app_context():
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    teacher_user = User(username=username, password=hashed_password, role='teacher')
    
    # Add to the database
    db.session.add(teacher_user)
    db.session.commit()
    print("Teacher account created successfully!")
