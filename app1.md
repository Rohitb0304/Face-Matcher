# from flask import Flask, render_template, request, redirect, url_for, session, flash
# from werkzeug.security import generate_password_hash, check_password_hash
# from models import db, Admin, Event, Image
# from config import Config
# from werkzeug.utils import secure_filename
# import cloudinary
# import cloudinary.uploader
# import random
# import string
# import requests
# import io
# import face_recognition
# from PIL import Image as PILImage
# from datetime import datetime
# from flask_migrate import Migrate

# app = Flask(__name__)
# app.config.from_object(Config)

# # Initialize database and migration
# db.init_app(app)
# migrate = Migrate(app, db)

# MAX_SIZE_MB = 10
# MAX_PIXELS = (1920, 1080)

# cloudinary.config(
#     cloud_name=Config.CLOUD_NAME,
#     api_key=Config.API_KEY,
#     api_secret=Config.API_SECRET
# )

# # Helper function to generate a unique event ID
# def generate_unique_event_id(event_name):
#     unique_event_id = f"{event_name.lower().replace(' ', '-')}-{random.randint(1000, 9999)}"
    
#     # Ensure the event ID is unique by checking the database
#     while Event.query.filter_by(unique_id=unique_event_id).first():
#         unique_event_id = f"{event_name.lower().replace(' ', '-')}-{random.randint(1000, 9999)}"
    
#     return unique_event_id


# @app.route('/')
# def index():
#     events = Event.query.all()  # Fetch all events from the database
#     return render_template('home.html', events=events)


# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         confirm_password = request.form['confirm_password']

#         if password != confirm_password:
#             flash("Passwords don't match!")
#             return redirect(url_for('register'))

#         hashed_password = generate_password_hash(password)
#         new_admin = Admin(username=username, password_hash=hashed_password)
#         db.session.add(new_admin)
#         db.session.commit()

#         flash('Admin created successfully! Please log in.')
#         return redirect(url_for('login'))

#     return render_template('register.html')


# @app.route('/events')
# def events():
#     # Code to fetch and display events
#     return render_template('events.html')


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']

#         admin = Admin.query.filter_by(username=username).first()
#         if admin and check_password_hash(admin.password_hash, password):
#             session['admin'] = admin.id
#             return redirect(url_for('dashboard'))

#         flash('Invalid credentials')
#         return redirect(url_for('login'))

#     return render_template('login.html')


# @app.route('/dashboard')
# def dashboard():
#     if not session.get('admin'):
#         return redirect(url_for('login'))

#     admin_id = session['admin']
#     events = Event.query.filter_by(admin_id=admin_id).all()
#     return render_template('dashboard.html', events=events)

# @app.route('/manage_event/<string:event_id>', methods=['GET', 'POST'])
# def manage_event(event_id):
#     event = Event.query.filter_by(unique_id=event_id).first_or_404()
#     images = Image.query.filter_by(event_id=event.id).all()

#     if request.method == 'POST':
#         event_name = request.form['event_name']
#         event_date = request.form['event_date']
#         event.name = event_name
#         event.date = event_date
#         db.session.commit()
#         flash('Event details updated successfully!', 'success')
#         return redirect(url_for('manage_event', event_id=event.unique_id))

#     return render_template('manage_event.html', event=event, images=images)

# @app.route('/user_upload', methods=['GET', 'POST'])
# def user_upload():
#     # Step 1: Handle Event ID form submission for GET request
#     if request.method == 'GET' and 'event_id' in request.args:
#         event_id = request.args.get('event_id')
#         event = Event.query.filter_by(unique_id=event_id).first()
        
#         # If the event is not found, redirect back with an error message
#         if not event:
#             flash("Event not found. Please check the Event ID and try again.")
#             return redirect(url_for('user_upload'))
        
#         # If the event is found, render the page with the event details and face upload form
#         return render_template('user_upload.html', event=event)
    
#     # Step 2: Handle face image upload in POST request
#     if request.method == 'POST' and 'event_id' in request.form:
#         event_id = request.form.get('event_id')
#         event = Event.query.filter_by(unique_id=event_id).first_or_404()

#         # Ensure a file is uploaded
#         if 'file' not in request.files or request.files['file'].filename == '':
#             flash('Please select a file to upload.')
#             return redirect(url_for('user_upload', event_id=event_id))

#         # Process the uploaded image
#         file = request.files['file']
#         uploaded_image = face_recognition.load_image_file(file)
#         uploaded_encoding = face_recognition.face_encodings(uploaded_image)
        
#         if not uploaded_encoding:
#             flash('No face found in the uploaded image. Please try again.')
#             return redirect(url_for('user_upload', event_id=event_id))
        
#         uploaded_encoding = uploaded_encoding[0]
#         matched_images = []

#         # Check the event's images for a match
#         for db_image in Image.query.filter_by(event_id=event.id).all():
#             response = requests.get(db_image.cloudinary_url)
#             db_image_file = face_recognition.load_image_file(io.BytesIO(response.content))
#             db_encoding = face_recognition.face_encodings(db_image_file)
            
#             if db_encoding and face_recognition.compare_faces([db_encoding[0]], uploaded_encoding, tolerance=0.6)[0]:
#                 matched_images.append(db_image)

#         # Show matched images and pass 'event' to the template
#         return render_template('user_results.html', matched_images=matched_images, event=event)

#     # Default render without event or file upload
#     return render_template('user_upload.html')


# @app.route('/admin_upload/<string:event_id>', methods=['POST'])
# def admin_upload(event_id):
#     try:
#         # Fetch the event and admin from the database
#         event = Event.query.filter_by(unique_id=event_id).first_or_404()
#         admin = Admin.query.get(session['admin'])

#         # Check if 'files' are in the request
#         if 'files' not in request.files:
#             flash('No files part')
#             return redirect(url_for('manage_event', event_id=event.unique_id))

#         # Get the list of files
#         files = request.files.getlist('files')

#         # Process each file
#         for file in files:
#             if file.filename == '':
#                 flash('Empty file detected, skipping.')
#                 continue

#             # Secure the filename
#             filename = secure_filename(file.filename)

#             # Generate a unique public_id for Cloudinary
#             unique_filename = f"{admin.username}_{event.unique_id}_{random.randint(1000, 9999)}"
#             folder_name = f"{admin.username}_{event.unique_id}"

#             # Upload to Cloudinary
#             upload_result = cloudinary.uploader.upload(
#                 file,
#                 folder=folder_name,
#                 public_id=unique_filename,
#                 use_filename=True,
#                 unique_filename=True
#             )

#             # Log Cloudinary response for debugging
#             print(f"Cloudinary Upload Result: {upload_result}")

#             # Save image details to the database
#             new_image = Image(
#                 filename=filename,
#                 cloudinary_url=upload_result['secure_url'],
#                 public_id=upload_result['public_id'],
#                 event_id=event.id
#             )
#             db.session.add(new_image)

#         # Commit to save the image information
#         db.session.commit()
#         flash('Images uploaded successfully!')

#     except Exception as e:
#         print(f"Error during upload: {e}")
#         flash('An error occurred during upload.', 'error')

#     return redirect(url_for('manage_event', event_id=event.unique_id))

# @app.route('/create_event', methods=['GET', 'POST'])
# def create_event():
#     if not session.get('admin'):
#         return redirect(url_for('login'))

#     if request.method == 'POST':
#         event_name = request.form['event_name']
#         event_date_str = request.form['event_date']

#         try:
#             event_date = datetime.strptime(event_date_str, '%Y-%m-%d').date()
#         except ValueError:
#             flash("Invalid date format. Please use YYYY-MM-DD.")
#             return redirect(url_for('create_event'))

#         # Generate a unique event ID
#         unique_event_id = generate_unique_event_id(event_name)

#         admin_id = session['admin']
#         new_event = Event(name=event_name, date=event_date, admin_id=admin_id, unique_id=unique_event_id)
#         db.session.add(new_event)
#         db.session.commit()

#         flash("Event created successfully!")
#         return redirect(url_for('dashboard'))

#     return render_template('create_event.html')

# @app.route('/delete_image/<int:image_id>', methods=['POST'])
# def delete_image(image_id):
#     image = Image.query.get_or_404(image_id)
#     try:
#         # Delete image from Cloudinary
#         cloudinary.uploader.destroy(image.public_id)

#         # Remove image from the database
#         db.session.delete(image)
#         db.session.commit()

#         flash('Image deleted successfully!', 'success')
#     except Exception as e:
#         flash(f'Error deleting image: {e}', 'danger')

#     return redirect(request.referrer)

# @app.route('/logout')
# def logout():
#     session.pop('admin', None)
#     flash('You have been logged out.')
#     return redirect(url_for('index'))


# if __name__ == '__main__':
#     app.run(debug=True)