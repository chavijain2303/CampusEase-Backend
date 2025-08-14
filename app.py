import os
from flask import Flask, request, jsonify, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta 
from flask_restful import Api
from sqlalchemy.exc import SQLAlchemyError
import traceback
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace('postgres://', 'postgresql://') if os.environ.get('DATABASE_URL') else 'sqlite:///app.db'

# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB limit

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
api = Api(app)

CORS(app, resources={
    r"/api/*": {
        "origins": "http://localhost:3000",
        "supports_credentials": True,
        "allow_headers": ["Authorization", "Content-Type"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    }
})

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    contact = db.Column(db.String(10), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    position = db.Column(db.String(50), nullable=False)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    course = db.Column(db.String(50), nullable=False)
    section = db.Column(db.String(10), nullable=False)
    enrollment = db.Column(db.String(11), unique=True, nullable=False)
    passing_year = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    contact = db.Column(db.String(10), nullable=False)
    dob = db.Column(db.String(10), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    profile_image_url = db.Column(db.String(200))  # Add this line

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    time = db.Column(db.String(10), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    availability = db.Column(db.String(20), default='all')
    batch = db.Column(db.String(50))
    course = db.Column(db.String(50))
    branch = db.Column(db.String(50))
    event_type = db.Column(db.String(20), default='Technical')  # New field
    cost = db.Column(db.String(20), default='Unpaid')         # New field
    is_competition = db.Column(db.Boolean, default=False)  # New field
    registrations_count = db.Column(db.Integer, default=0, nullable=False)
    attendance_count = db.Column(db.Integer, default=0, nullable=False)
    organizer = db.Column(db.Integer, nullable=False)
    
    # Relationships
    registrations = db.relationship('Registration', backref='event', cascade='all, delete-orphan')
    attendances = db.relationship('Attendance', backref='event', cascade='all, delete-orphan')


class Registration(db.Model):
    __tablename__ = 'registrations'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    event_name = db.Column(db.String(100), nullable=False)  # New field
    name = db.Column(db.String(100), nullable=False)
    enrollment_number = db.Column(db.String(11), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)

class Attendance(db.Model):
    __tablename__ = 'attendance'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    event_name = db.Column(db.String(100), nullable=False)  # New field
    name = db.Column(db.String(100), nullable=False)
    enrollment_number = db.Column(db.String(11), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    marked_at = db.Column(db.DateTime, default=datetime.utcnow)

class CompetitionResults(db.Model):
    __tablename__ = 'competition_results'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    winner = db.Column(db.String(100), nullable=False)
    runner_up = db.Column(db.String(100), nullable=False)
    posted_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    event = db.relationship('Event', backref='results')

class ContactQuery(db.Model):
    __tablename__ = 'contact_queries'
    id = db.Column(db.Integer, primary_key=True)
    student_name = db.Column(db.String(100), nullable=False)
    enrollment_number = db.Column(db.String(11), nullable=False)
    admin_name = db.Column(db.String(100), nullable=False)
    concern = db.Column(db.Text, nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Pending')  # Pending, Resolved, etc.

class Feedback(db.Model):
    __tablename__ = 'feedback'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, nullable=False)
    student_id = db.Column(db.Integer, nullable=False)
    student_name = db.Column(db.String(100), nullable=False)
    enrollment_number = db.Column(db.String(11), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comments = db.Column(db.Text)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/api/events/<int:event_id>/attendance-check', methods=['GET'])
def check_attendance(event_id):
    try:
        # Authentication check
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header.split(' ')[1]
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        # Get student
        student = Student.query.get(decoded['id'])
        if not student:
            return jsonify({"error": "Student not found"}), 404

        # Check attendance
        attendance = Attendance.query.filter_by(
            event_id=event_id,
            enrollment_number=student.enrollment
        ).first()

        if not attendance:
            return jsonify({"error": "Attendance not verified for this event"}), 403

        return jsonify({"message": "Attendance verified"}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def allowed_file(filename):
    """Check if the file has an allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/api/student/profile', methods=['GET'])
def get_student_profile():
    try:
        # Authentication check
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header.split(' ')[1]
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        # Get student with all fields
        student = Student.query.get(decoded['id'])
        if not student:
            return jsonify({"error": "Student not found"}), 404

        # Prepare complete response data
        profile_data = {
            "id": student.id,
            "name": student.name,
            "email": student.email,
            "contact": student.contact,
            "enrollment": student.enrollment,
            "course": student.course,
            "section": student.section,
            "passing_year": student.passing_year,
            "dob": student.dob,
            "profileImage": f"/uploads/{student.profile_image_url.split('/')[-1]}" if student.profile_image_url else None
        }

        return jsonify(profile_data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/api/logout', methods=['POST'])
def logout():
    try:
        # The actual logout is handled client-side by removing the token
        # This endpoint can be used for server-side cleanup if needed
        return jsonify({"message": "Logout successful"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/student/profile', methods=['PUT'])
def update_student_profile():
    try:
        # Authentication check
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header.split(' ')[1]
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        student = Student.query.get(decoded['id'])
        if not student:
            return jsonify({"error": "Student not found"}), 404

        # Handle file upload
        if 'profileImage' in request.files:
            file = request.files['profileImage']
            if file and file.filename != '':
                if not allowed_file(file.filename):
                    return jsonify({"error": "Invalid file type"}), 400
                
                # ... file handling logic ...

        # Update all fields from form data
        if request.form:
            student.name = request.form.get('name', student.name)
            student.contact = request.form.get('contact', student.contact)
            student.section = request.form.get('section', student.section)
            # Add other fields as needed

        db.session.commit()

        # Return complete updated profile
        return jsonify({
            "message": "Profile updated successfully",
            "user": {
                "id": student.id,
                "name": student.name,
                "email": student.email,
                "contact": student.contact,
                "enrollment": student.enrollment,
                "course": student.course,
                "section": student.section,
                "passing_year": student.passing_year,
                "dob": student.dob,
                "profileImage": student.profile_image_url
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/uploads/<filename>')
def serve_uploaded_file(filename):
    """Serve uploaded profile pictures"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/admin/profile', methods=['GET'])
def get_admin_profile():
    try:
        # Authentication check
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header.split(' ')[1]
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if decoded.get('role') != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        
        # Get admin with all fields
        admin = Admin.query.get(decoded['id'])
        if not admin:
            return jsonify({"error": "Admin not found"}), 404

        # Prepare complete response data
        profile_data = {
            "id": admin.id,
            "name": admin.name,
            "email": admin.email,
            "contact": admin.contact,
            "position": admin.position
        }

        return jsonify(profile_data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/api/admin/profile', methods=['PUT'])
def update_admin_profile():
    try:
        # Authentication check
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header.split(' ')[1]
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if decoded.get('role') != 'admin':
            return jsonify({"error": "Admin access required"}), 403

        admin = Admin.query.get(decoded['id'])
        if not admin:
            return jsonify({"error": "Admin not found"}), 404

        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Update fields from request data
        if 'name' in data:
            admin.name = data['name']
        if 'contact' in data:
            admin.contact = data['contact']
        if 'position' in data:
            admin.position = data['position']

        db.session.commit()

        return jsonify({
            "message": "Profile updated successfully",
            "user": {
                "id": admin.id,
                "name": admin.name,
                "email": admin.email,
                "contact": admin.contact,
                "position": admin.position
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
    

@app.route('/api/certificates/generate', methods=['POST'])
def generate_certificate():
    try:
        # Authentication check
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header.split(' ')[1]
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        # Get student and event data
        data = request.get_json()
        if not data or 'event_id' not in data:
            return jsonify({"error": "Event ID is required"}), 400

        student = Student.query.get(decoded['id'])
        if not student:
            return jsonify({"error": "Student not found"}), 404

        event = Event.query.get(data['event_id'])
        if not event:
            return jsonify({"error": "Event not found"}), 404

        # Check if student attended the event
        attendance = Attendance.query.filter_by(
            event_id=event.id,
            enrollment_number=student.enrollment
        ).first()
        
        if not attendance:
            return jsonify({"error": "Attendance not verified for this event"}), 403

        # Create certificate data
        certificate_data = {
            "student_name": student.name,
            "enrollment_number": student.enrollment,
            "event_name": event.title,
            "event_date": event.date,
            "certificate_id": f"CERT-{event.id}-{student.enrollment}",
            "issued_date": datetime.now().strftime("%Y-%m-%d")
        }

        return jsonify(certificate_data), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/api/feedback', methods=['POST'])
def submit_feedback():
    try:
        # Authentication check
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header.split(' ')[1]
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Get student
        student = Student.query.get(decoded['id'])
        if not student:
            return jsonify({"error": "Student not found"}), 404

        # Verify attendance
        attendance = Attendance.query.filter_by(
            event_id=data['eventId'],
            enrollment_number=student.enrollment
        ).first()
        
        if not attendance:
            return jsonify({"error": "Attendance not verified for this event"}), 403

        # Create feedback (you'll need to create a Feedback model)
        new_feedback = Feedback(
            event_id=data['eventId'],
            student_id=student.id,
            student_name=data['studentName'],
            enrollment_number=data['enrollmentNumber'],
            rating=data['rating'],
            comments=data['comments'],
            submitted_at=datetime.utcnow()
        )

        db.session.add(new_feedback)
        db.session.commit()

        return jsonify({
            "message": "Feedback submitted successfully",
            "feedback_id": new_feedback.id
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/contact', methods=['POST'])
def submit_contact_query():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Validate required fields
        required_fields = ['name', 'enrollmentNumber', 'adminName', 'concern']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({"error": f"Missing fields: {', '.join(missing_fields)}"}), 400

        # Create new contact query
        new_query = ContactQuery(
            student_name=data['name'],
            enrollment_number=data['enrollmentNumber'],
            admin_name=data['adminName'],
            concern=data['concern']
        )

        db.session.add(new_query)
        db.session.commit()

        return jsonify({
            "message": "Your concern has been submitted successfully!",
            "query_id": new_query.id
        }), 201

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"error": "Database error", "details": str(e)}), 500
    except Exception as e:
        return jsonify({"error": "Server error", "details": str(e)}), 500
    
@app.route('/api/admin/queries', methods=['GET'])
def get_all_queries():
    try:
        # Authentication check
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header.split(' ')[1]
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if decoded.get('role') != 'admin':
            return jsonify({"error": "Admin access required"}), 403

        # Get all queries
        queries = ContactQuery.query.order_by(ContactQuery.submitted_at.desc()).all()
        
        return jsonify([{
            "id": q.id,
            "student_name": q.student_name,
            "enrollment_number": q.enrollment_number,
            "admin_name": q.admin_name,
            "concern": q.concern,
            "submitted_at": q.submitted_at.isoformat(),
            "status": q.status
        } for q in queries]), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/queries/<int:query_id>/status', methods=['PATCH'])
def update_query_status(query_id):
    try:
        # Authentication check
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header.split(' ')[1]
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if decoded.get('role') != 'admin':
            return jsonify({"error": "Admin access required"}), 403

        data = request.get_json()
        if not data or 'status' not in data:
            return jsonify({"error": "Status is required"}), 400

        # Validate status
        valid_statuses = ['Pending', 'In Progress', 'Resolved']
        if data['status'] not in valid_statuses:
            return jsonify({"error": "Invalid status"}), 400

        # Update query
        query = ContactQuery.query.get(query_id)
        if not query:
            return jsonify({"error": "Query not found"}), 404

        query.status = data['status']
        db.session.commit()

        return jsonify({
            "message": "Status updated successfully",
            "new_status": query.status
        }), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/events/<int:event_id>/results', methods=['POST'])
def post_event_results(event_id):
    try:
        # Authentication check
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header.split(' ')[1]
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if decoded.get('role') != 'admin':
            return jsonify({"error": "Admin access required"}), 403

        # Get the event
        event = Event.query.get(event_id)
        if not event:
            return jsonify({"error": "Event not found"}), 404

        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Validate required fields
        required_fields = ['winner', 'runnerUp']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({"error": f"Missing fields: {', '.join(missing_fields)}"}), 400

        # Check if results already exist for this event
        existing_results = CompetitionResults.query.filter_by(event_id=event_id).first()
        if existing_results:
            return jsonify({"error": "Results already posted for this event"}), 409

        # Create new results entry
        new_results = CompetitionResults(
            event_id=event_id,
            winner=data['winner'],
            runner_up=data['runnerUp']
        )

        db.session.add(new_results)
        db.session.commit()

        return jsonify({
            "message": "Results posted successfully",
            "results_id": new_results.id
        }), 201

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"error": "Database error", "details": str(e)}), 500
    except Exception as e:
        return jsonify({"error": "Server error", "details": str(e)}), 500
    
@app.route('/api/events/<int:event_id>/results', methods=['GET'])
def get_event_results(event_id):
    try:
        # Get the event
        event = Event.query.get(event_id)
        if not event:
            return jsonify({"error": "Event not found"}), 404

        # Get results for this event
        results = CompetitionResults.query.filter_by(event_id=event_id).first()
        if not results:
            return jsonify({"error": "No results available for this event"}), 404

        return jsonify({
            "event_id": event.id,
            "event_name": event.title,
            "winner": results.winner,
            "runner_up": results.runner_up,
            "posted_at": results.posted_at.isoformat()
        }), 200

    except Exception as e:
        return jsonify({"error": "Server error", "details": str(e)}), 500

# Add this new route
@app.route('/api/events/<int:event_id>/attend', methods=['POST'])
def mark_attendance(event_id):
    try:
        # Authentication
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header.split(' ')[1]
        try:
            decoded = jwt.decode(
                token, 
                app.config['SECRET_KEY'], 
                algorithms=['HS256'],
                options={'require': ['exp', 'id']}
            )
            student_id = decoded['id']
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Session expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        # Get student and event
        student = Student.query.get(student_id)
        if not student:
            return jsonify({"error": "Student not found"}), 404

        event = Event.query.get(event_id)
        if not event:
            return jsonify({"error": "Event not found"}), 404

        # Check registration
        registration = Registration.query.filter_by(
            event_id=event_id,
            enrollment_number=student.enrollment
        ).first()
        if not registration:
            return jsonify({"error": "Registration required"}), 403

        # Check existing attendance
        existing = Attendance.query.filter_by(
            event_id=event_id,
            enrollment_number=student.enrollment
        ).first()
        if existing:
            return jsonify({"error": "Attendance already marked"}), 409

        # Create attendance
        new_attendance = Attendance(
            event_id=event_id,
            event_name=event.title,  # Add event title
            name=student.name,       # Student's name
            enrollment_number=student.enrollment,
            email=student.email      # Student's email
        )

        event.attendance_count = Attendance.query.filter_by(event_id=event_id).count() + 1
        db.session.add(new_attendance)
        db.session.commit()

        return jsonify({
            "message": "Attendance marked successfully",
            "attendance_id": new_attendance.id
        }), 201

    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f'Database error: {str(e)}')
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error: {traceback.format_exc()}')
        return jsonify({"error": "Server error"}), 500

@app.route('/api/events/<int:event_id>/attendance', methods=['GET'])
def get_event_attendance(event_id):
    try:
        # Admin auth
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Authorization required'}), 401

        token = auth_header.split(' ')[1]
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if decoded.get('role') != 'admin':
            return jsonify({'error': 'Admin access required'}), 403

        # Get attendance with student details
        records = db.session.query(Attendance, Student)\
            .join(Student, Student.enrollment == Attendance.enrollment_number)\
            .filter(Attendance.event_id == event_id)\
            .all()

        result = [{
            "name": student.name,
            "enrollment": student.enrollment,
            "email": student.email,
            "course": student.course,
            "section": student.section,
            "contact": student.contact,
            "event": att.event_name,
            "marked_at": att.marked_at.isoformat()
        } for att, student in records]

        return jsonify(result), 200

    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        app.logger.error(f'Error: {str(e)}')
        return jsonify({"error": "Server error"}), 500
    
@app.route('/api/events/<int:event_id>/register', methods=['POST'])
def register_for_event(event_id):
    try:
        # Authentication and Authorization Check
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            app.logger.warning('Missing or invalid Authorization header')
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header.split(' ')[1]
        try:
            decoded = jwt.decode(
                token, 
                app.config['SECRET_KEY'], 
                algorithms=['HS256'],
                options={'require': ['exp', 'id']}
            )
            student_id = decoded['id']
        except jwt.ExpiredSignatureError:
            app.logger.warning('Expired JWT token')
            return jsonify({"error": "Session expired"}), 401
        except jwt.InvalidTokenError as e:
            app.logger.error(f'Invalid token: {str(e)}')
            return jsonify({"error": "Invalid authentication token"}), 401

        # Student Verification
        student = Student.query.get(student_id)
        if not student:
            app.logger.error(f'Student not found with ID: {student_id}')
            return jsonify({"error": "Student account not found"}), 404

        # Event Verification
        event = Event.query.get(event_id)
        if not event:
            app.logger.error(f'Event not found with ID: {event_id}')
            return jsonify({"error": "Event not found"}), 404

        # Existing Registration Check
        existing_reg = Registration.query.filter_by(
            event_id=event_id,
            enrollment_number=student.enrollment
        ).first()
        if existing_reg:
            app.logger.info(f'Duplicate registration attempt by {student.enrollment}')
            return jsonify({"error": "Already registered for this event"}), 409

        # Create New Registration
        new_registration = Registration(
            event_id=event_id,
            event_name=event.title,  # Add event name
            name=student.name,
            enrollment_number=student.enrollment,
            email=student.email
        )

        # Update Registration Count
        event.registrations_count += 1

        db.session.add(new_registration)
        # db.session.add(event)
        db.session.commit()

        app.logger.info(f'New registration ID: {new_registration.id}')
        return jsonify({
            "message": "Registration successful",
            "registration_id": new_registration.id,
            "event_title": event.title
        }), 201

    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f'Database error: {str(e)}\n{traceback.format_exc()}')
        return jsonify({
            "error": "Database operation failed",
            "details": str(e)
        }), 500
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Unexpected error: {traceback.format_exc()}')
        return jsonify({
            "error": "Internal server error",
            "details": "Please check server logs"
        }), 500

# to display registered students list in admin event list
@app.route('/api/events/<int:event_id>/registrations', methods=['GET'])  # Remove OPTIONS
def get_event_registrations(event_id):
    
    try:
        # Authentication check
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Authorization header is required'}), 401

        # Verify JWT token
        token = auth_header.split(' ')[1]
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        # Authorization check (must be admin)
        if decoded.get('role') != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403

        # Get registrations with student details
        registrations = Registration.query.filter_by(event_id=event_id).all()

        # Format the response
        result = []
        for reg in registrations:
            result.append({
                "name": reg.name,
                "enrollment": reg.enrollment_number,
                "email": reg.email,
                "event": reg.event_name,
                "registration_date": reg.registration_date.isoformat()
            })

        return jsonify(result), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f'Database error: {str(e)}')
        return jsonify({"error": "Database error", "details": str(e)}), 500
    except Exception as e:
        app.logger.error(f'Unexpected error: {str(e)}')
        return jsonify({"error": "Server error", "details": str(e)}), 500

@app.route('/api/admin/signup', methods=['POST'])
def admin_signup():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        required_fields = ['name', 'email', 'contactNumber', 'password', 'position']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({"error": f"Missing fields: {', '.join(missing_fields)}"}), 400

        if Admin.query.filter_by(email=data['email']).first():
            return jsonify({"error": "Email already exists"}), 409

        hashed_password = generate_password_hash(data['password'])
        
        new_admin = Admin(
            name=data['name'],
            email=data['email'],
            contact=data['contactNumber'],
            password=hashed_password,
            position=data['position']
        )
        
        db.session.add(new_admin)
        db.session.commit()
        
        return jsonify({
            "message": "Admin created successfully",
            "redirect": "/login-admin"  # Ensure this matches frontend route
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    try:
        data = request.get_json()
        admin = Admin.query.filter_by(email=data['email']).first()
        
        if not admin or not check_password_hash(admin.password, data['password']):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        token = jwt.encode({
            'id': admin.id,
            'role': 'admin',  # Add role claim
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'token': token,
            'user': {
                'id': admin.id,
                'name': admin.name,
                'email': admin.email,
                'role': 'admin'
            },
            'redirect': '/admin'  # Changed from '/admin-dashboard'
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/student/signup', methods=['POST'])
def student_signup():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Add validation for required fields
        required_fields = ['name', 'course', 'section', 'enrollmentNumber',
                          'passingYear', 'email', 'contactNumber', 
                          'dateOfBirth', 'password']
        
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({"error": f"Missing fields: {', '.join(missing_fields)}"}), 400

        # Check for existing email or enrollment number
        if Student.query.filter_by(email=data['email']).first():
            return jsonify({"error": "Email already registered"}), 409
            
        if Student.query.filter_by(enrollment=data['enrollmentNumber']).first():
            return jsonify({"error": "Enrollment number already exists"}), 409

        hashed_password = generate_password_hash(data['password'])
        
        new_student = Student(
            name=data['name'],
            course=data['course'],
            section=data['section'],
            enrollment=data['enrollmentNumber'],
            passing_year=data['passingYear'],
            email=data['email'],
            contact=data['contactNumber'],
            dob=data['dateOfBirth'],
            password=hashed_password
        )
        
        db.session.add(new_student)
        db.session.commit()
        
        return jsonify({
            "message": "Student created successfully",
            "id": new_student.id,
            "redirect": "/login-student"  # Add redirect path
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/student/login', methods=['POST'])
def student_login():
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400
    
    data = request.get_json()
    student = Student.query.filter_by(email=data['email']).first()
    
    if not student or not check_password_hash(student.password, data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Corrected datetime usage
    token = jwt.encode({
        'id': student.id,
        'role': 'student',  # Add role claim
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({
        'token': token,
        'user': {
            'id': student.id,
            'name': student.name,
             'enrollment': student.enrollment,
            'email': student.email,
            'role': 'student'
        },
        'redirect': '/student-dashboard'  # Add redirect for consistency
    }), 200


@app.route('/api/events', methods=['GET', 'POST'])
def handle_events():
    if request.method == 'POST':
        data = request.get_json()
        
        # Validate conditional fields for specific availability
        if data.get('availability') == 'specific':
            if not data.get('batch') or not data.get('course'):
                return jsonify({"error": "Batch and course are required for specific availability"}), 400
            if data.get('course') == 'Btech' and not data.get('branch'):
                return jsonify({"error": "Branch is required for B.Tech events"}), 400

        new_event = Event(
            title=data['title'],
            date=data['date'],
            time=data['time'],
            location=data['location'],
            description=data['description'],
            availability=data.get('availability', 'all'),
            event_type=data.get('eventType', 'Technical'),
            cost=data.get('cost', 'Unpaid'),
            is_competition=data.get('isCompetition', False),  # New field
            organizer=data['organizer'],
            batch=data.get('batch'),
            course=data.get('course'),
            branch=data.get('branch'),
            registrations_count=data.get('registrations_count', 0),
            attendance_count=data.get('attendance_count', 0)
        )
        
        db.session.add(new_event)
        db.session.commit()
        return jsonify({
            "message": "Event created successfully",
            "event_id": new_event.id
        }), 201
    
    if request.method == 'GET':
        query = Event.query
        availability_filter = request.args.get('availability')
        
        if availability_filter:
            query = query.filter_by(availability=availability_filter)
            
        events = query.all()
        
        return jsonify([{
            "id": event.id,
            "title": event.title,
            "date": event.date,
            "time": event.time,
            "location": event.location,
            "description": event.description,
            "availability": event.availability,
            "eventType": event.event_type,
            "cost": event.cost,
            "isCompetition": event.is_competition,  # New field
            "batch": event.batch,
            "course": event.course,
            "branch": event.branch,
            "registrations_count": event.registrations_count,
            "attendance_count": event.attendance_count,
            "organizer": event.organizer
        } for event in events]), 200

@app.route('/api/events/<int:event_id>', methods=['GET'])
def get_event(event_id):
    try:
        event = Event.query.get(event_id)
        if not event:
            return jsonify({"error": "Event not found"}), 404
            
        return jsonify({
            "id": event.id,
            "title": event.title,
            "date": event.date,
            "time": event.time,
            "location": event.location,
            "description": event.description,
            "availability": event.availability,
            "eventType": event.event_type,
            "cost": event.cost,
            "isCompetition": event.is_competition,  # New field
            "batch": event.batch,
            "course": event.course,
            "branch": event.branch,
            "registrations_count": event.registrations_count,
            "attendance_count": event.attendance_count,
            "organizer": event.organizer
        }), 200
        
    except Exception as e:
        return jsonify({"error": "Server error", "details": str(e)}), 500
    
@app.route('/api/events/delete/<int:event_id>', methods=['DELETE'])  # DELETE-only endpoint
def delete_event(event_id):
    try:
        # Authentication check (Admin only)
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header.split(' ')[1]
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if decoded.get('role') != 'admin':
            return jsonify({"error": "Admin access required"}), 403

        # Find and delete the event
        event = Event.query.get(event_id)
        if not event:
            return jsonify({"error": "Event not found"}), 404

        db.session.delete(event)
        db.session.commit()

        return jsonify({"message": "Event deleted successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


    
# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5000, debug=True)
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port)
else:
    # This is important for Vercel deployment
    gunicorn_app = app