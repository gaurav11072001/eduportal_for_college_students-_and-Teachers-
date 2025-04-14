from app import db, User

def create_student_user():
    # Define username and password for the student
    username = "student1"
    password = "student123"
    role = "student"
    
    # Check if the user already exists
    existing_user = User.query.filter_by(username=username).first()
    if not existing_user:
        # Create a new user with role 'student'
        student = User(username=username, password=password, role=role)
        db.session.add(student)
        db.session.commit()
        print("Student user created successfully!")
    else:
        print("User already exists.")

if __name__ == '__main__':
    from app import app
    with app.app_context():
        create_student_user()
