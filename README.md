# EduPortal - Educational Institution Management System

## Overview
EduPortal is a comprehensive web-based platform designed to streamline educational institution management. It provides separate interfaces for students and teachers, facilitating various academic and administrative tasks.

## Features

### For Students
- **Account Management**
  - Register as a student
  - Login with email and role verification
  - View and manage personal profile

- **Academic Features**
  - Take online exams with timer functionality
  - View exam scores and performance analytics
  - Access semester results with grade cards
  - Download marksheets and academic documents

- **Co-curricular Activities**
  - Register for sports events and activities
  - View upcoming events and notices
  - Track participation in various activities

### For Teachers
- **Account Management**
  - Register as a teacher
  - Secure login system
  - Manage profile and credentials

- **Academic Management**
  - Create and manage exam questions
  - Set exam time limits and parameters
  - Upload semester results
  - Attach marksheets and documents
  - View student performance analytics

- **Administrative Features**
  - Post important notices
  - Manage sports events and activities
  - View student registrations and participations
  - Delete or modify academic records

## Technical Stack

- **Backend**
  - Flask (Python web framework)
  - SQLAlchemy (Database ORM)
  - Flask-Login (Authentication)
  - Flask-WTF (Form handling and CSRF protection)
  - Flask-Bcrypt (Password hashing)

- **Frontend**
  - HTML5, CSS3, JavaScript
  - Bootstrap 5
  - Font Awesome icons
  - Custom responsive design

- **Database**
  - SQLite (with backup functionality)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd eduportal
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Initialize the database:
```bash
python db_update.py
```

4. Run the application:
```bash
python app.py
```

## Configuration

1. Database setup is handled automatically through `db_update.py`
2. Default configurations can be modified in `config.py`
3. Static files should be placed in the `static` directory
4. Templates are located in the `templates` directory

## Usage

1. Access the application through a web browser at `http://localhost:5000`
2. Register as either a student or teacher
3. Login with registered credentials
4. Navigate through the dashboard for respective features

## Security Features

- Password hashing using bcrypt
- CSRF protection for forms
- Role-based access control
- Secure file upload handling
- Session management
- Protected routes and endpoints

## File Structure

```
eduportal/
├── app.py              # Main application file
├── config.py           # Configuration settings
├── db_update.py        # Database management
├── models.py           # Database models
├── requirements.txt    # Project dependencies
├── static/            # Static files (CSS, JS, images)
│   ├── css/
│   ├── images/
│   └── uploads/
└── templates/         # HTML templates
    ├── login.html
    ├── dashboard/
    └── forms/
```



## Acknowledgments

- Bootstrap for the responsive UI components
- Flask community for the excellent documentation
- Contributors and testers who helped improve the system 