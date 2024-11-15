# import hashlib
# import random
# import string
# import io
# import zipfile
# import os
# from io import BytesIO
# import requests
# import qrcode
# import cloudinary
# import cloudinary.uploader
# from flask import Flask, render_template, request, redirect, send_file, url_for, session, flash, Response
# from werkzeug.security import generate_password_hash, check_password_hash
# from werkzeug.utils import secure_filename
# from models import db, Admin, Event, Image
# from config import Config
# from PIL import Image as PILImage
# from datetime import datetime
# import face_recognition
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

# # Route to display all events
# @app.route('/')
# def index():
#     events = Event.query.all()  # Fetch all events from the database
#     return render_template('home.html', events=events)

# # QR Code Generation Route
# @app.route('/generate_qr_code/<string:event_id>')
# def generate_qr_code(event_id):
#     event = Event.query.filter_by(unique_id=event_id).first_or_404()

#     # Generate QR code based on Event ID
#     qr = qrcode.QRCode(
#         version=1,
#         error_correction=qrcode.constants.ERROR_CORRECT_L,
#         box_size=10,
#         border=4,
#     )
#     qr.add_data(event.unique_id)
#     qr.make(fit=True)

#     img = qr.make_image(fill="black", back_color="white")

#     # Save QR code image to a BytesIO object
#     img_io = BytesIO()
#     img.save(img_io, 'PNG')
#     img_io.seek(0)

#     return Response(img_io, mimetype='image/png')

# # Image Hashing Function
# def image_hash(image_data):
#     """Generate a hash for the image to identify duplicates."""
#     img = PILImage.open(io.BytesIO(image_data))
#     img = img.convert("RGB")
#     img.thumbnail((100, 100))
#     hash_value = hashlib.md5(img.tobytes()).hexdigest()
#     return hash_value

# # Helper function to generate a unique event ID
# def generate_unique_event_id(event_name):
#     unique_event_id = f"{event_name.lower().replace(' ', '-')}-{random.randint(1000, 9999)}"
    
#     # Ensure the event ID is unique by checking the database
#     while Event.query.filter_by(unique_id=unique_event_id).first():
#         unique_event_id = f"{event_name.lower().replace(' ', '-')}-{random.randint(1000, 9999)}"
    
#     return unique_event_id

# # Register admin route
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

# # Admin login route
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

# # Admin dashboard route
# @app.route('/dashboard')
# def dashboard():
#     if not session.get('admin'):
#         return redirect(url_for('login'))

#     admin_id = session['admin']
#     events = Event.query.filter_by(admin_id=admin_id).all()
#     return render_template('dashboard.html', events=events)

# # Manage event route
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

# # User image upload route
# @app.route('/user_upload', methods=['GET', 'POST'])
# def user_upload():
#     if request.method == 'GET' and 'event_id' in request.args:
#         event_id = request.args.get('event_id')
#         event = Event.query.filter_by(unique_id=event_id).first()
        
#         if not event:
#             flash("Event not found. Please check the Event ID and try again.")
#             return redirect(url_for('user_upload'))
        
#         return render_template('user_upload.html', event=event)

#     if request.method == 'POST' and 'event_id' in request.form:
#         event_id = request.form.get('event_id')
#         event = Event.query.filter_by(unique_id=event_id).first_or_404()

#         if 'file' not in request.files or request.files['file'].filename == '':
#             flash('Please select a file to upload.')
#             return redirect(url_for('user_upload', event_id=event_id))

#         file = request.files['file']
#         uploaded_image = face_recognition.load_image_file(file)
#         uploaded_encoding = face_recognition.face_encodings(uploaded_image)

#         if not uploaded_encoding:
#             flash('No face found in the uploaded image. Please try again.')
#             return redirect(url_for('user_upload', event_id=event_id))

#         uploaded_encoding = uploaded_encoding[0]
#         matched_images = []

#         for db_image in Image.query.filter_by(event_id=event.id).all():
#             response = requests.get(db_image.cloudinary_url)
#             db_image_file = face_recognition.load_image_file(io.BytesIO(response.content))
#             db_encoding = face_recognition.face_encodings(db_image_file)

#             if db_encoding and face_recognition.compare_faces([db_encoding[0]], uploaded_encoding, tolerance=0.6)[0]:
#                 matched_images.append(db_image)

#         return render_template('user_results.html', matched_images=matched_images, event=event)

#     return render_template('user_upload.html')

# # import os
# # import random
# # import cloudinary
# # import cloudinary.uploader
# # from flask import flash, redirect, url_for, request
# # from werkzeug.utils import secure_filename
# from tempfile import NamedTemporaryFile
# import shutil

# @app.route('/admin_upload/<string:event_id>', methods=['POST'])
# def admin_upload(event_id):
#     try:
#         event = Event.query.filter_by(unique_id=event_id).first_or_404()
#         admin = Admin.query.get(session['admin'])

#         # Check if files are part of the request
#         if 'files' not in request.files:
#             flash('No files were uploaded.', 'error')
#             return redirect(url_for('manage_event', event_id=event.unique_id))

#         files = request.files.getlist('files')

#         if not files:
#             flash('No files selected for upload.', 'error')
#             return redirect(url_for('manage_event', event_id=event.unique_id))

#         for file in files:
#             if file.filename == '':
#                 flash('Empty file detected, skipping.', 'error')
#                 continue

#             filename = secure_filename(file.filename)
#             file_data = file.read()

#             # Debug: Log the file size and check for empty file
#             print(f"Uploading file {filename}, size: {len(file_data)} bytes")
            
#             # Skip file if it’s empty
#             if len(file_data) == 0:
#                 flash(f"The file {filename} is empty. Skipping.", 'error')
#                 continue

#             # Debug: Ensure that the file can be processed
#             print(f"File data for {filename} is valid, proceeding with upload.")

#             # Create a temporary file to pass to Cloudinary
#             with NamedTemporaryFile(delete=False, suffix='.jpg') as tmp_file:
#                 tmp_file.write(file_data)
#                 tmp_file_path = tmp_file.name

#             # Generate a unique filename for Cloudinary
#             unique_filename = f"{admin.username}_{event.unique_id}_{random.randint(1000, 9999)}"
#             folder_name = f"{admin.username}_{event.unique_id}"

#             try:
#                 # Upload the file to Cloudinary
#                 print(f"Attempting to upload {filename} to Cloudinary...")
#                 upload_result = cloudinary.uploader.upload(
#                     tmp_file_path,
#                     folder=folder_name,
#                     public_id=unique_filename,
#                     use_filename=True,
#                     unique_filename=True
#                 )

#                 # Log the result from Cloudinary
#                 print(f"Cloudinary upload result: {upload_result}")

#                 # Check if the upload was successful and has a valid URL
#                 if 'secure_url' in upload_result:
#                     secure_url = upload_result['secure_url']
#                     print(f"File uploaded successfully: {secure_url}")

#                     # Save the uploaded image to the database
#                     new_image = Image(
#                         filename=filename,
#                         cloudinary_url=secure_url,
#                         event_id=event.id
#                     )
#                     db.session.add(new_image)
#                     db.session.commit()

#                     flash(f"File {filename} uploaded successfully!", 'success')
#                 else:
#                     flash(f"Failed to upload {filename} to Cloudinary.", 'error')
#                     print(f"Upload failed for {filename}: {upload_result}")

#             except Exception as e:
#                 flash(f"Error during upload: {str(e)}", 'error')
#                 print(f"Error during upload for {filename}: {str(e)}")

#             # Clean up the temporary file
#             os.remove(tmp_file_path)

#         return redirect(url_for('manage_event', event_id=event.unique_id))

#     except Exception as e:
#         db.session.rollback()
#         flash(f"An unexpected error occurred: {str(e)}", 'error')
#         print(f"An unexpected error occurred: {str(e)}")
#         return redirect(url_for('manage_event', event_id=event.unique_id))

# # Delete image route
# @app.route('/delete_image/<int:image_id>', methods=['POST'])
# def delete_image(image_id):
#     image = Image.query.get_or_404(image_id)
#     try:
#         cloudinary.uploader.destroy(image.public_id)
#         db.session.delete(image)
#         db.session.commit()
#         flash('Image deleted successfully!', 'success')
#     except Exception as e:
#         flash(f'Error deleting image: {e}', 'danger')

#     return redirect(request.referrer)

# @app.route('/events')
# def events():
#     events = Event.query.all()  # Fetch all events from the database
#     return render_template('events.html', events=events)


# # Create event route
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

#         unique_event_id = generate_unique_event_id(event_name)

#         admin_id = session['admin']
#         new_event = Event(name=event_name, date=event_date, admin_id=admin_id, unique_id=unique_event_id)
#         db.session.add(new_event)
#         db.session.commit()

#         flash("Event created successfully!")
#         return redirect(url_for('dashboard'))

#     return render_template('create_event.html')

# # Route to download individual image
# @app.route('/download_image/<int:image_id>', methods=['GET'])
# def download_image(image_id):
#     # Fetch the image from the database
#     image = Image.query.get_or_404(image_id)
    
#     try:
#         # Send the file directly from Cloudinary
#         response = requests.get(image.cloudinary_url)
#         image_data = io.BytesIO(response.content)

#         # Serve the file to the user for download
#         return send_file(
#             image_data,
#             as_attachment=True,
#             download_name=image.filename,
#             mimetype='image/jpeg'
#         )

#     except Exception as e:
#         flash(f'Error downloading image: {e}', 'danger')
#         return redirect(request.referrer)

# # Route to download all matched images as a zip file
# @app.route('/download_images_zip/<string:event_id>', methods=['GET'])
# def download_images_zip(event_id):
#     event = Event.query.filter_by(unique_id=event_id).first_or_404()
    
#     # Get all matched images for the event
#     matched_images = Image.query.filter_by(event_id=event.id).all()
    
#     # Create a BytesIO object to store the zip file in memory
#     zip_io = BytesIO()

#     with zipfile.ZipFile(zip_io, 'w', zipfile.ZIP_DEFLATED) as zip_file:
#         for image in matched_images:
#             # Download image from Cloudinary
#             response = requests.get(image.cloudinary_url)
            
#             if response.status_code == 200:
#                 # Write each image to the zip file
#                 zip_file.writestr(image.filename, response.content)

#     # Rewind the BytesIO object to the beginning so it can be read
#     zip_io.seek(0)

#     # Serve the zip file to the user for download
#     return send_file(
#         zip_io,
#         as_attachment=True,
#         download_name=f"{event.name}_matched_images.zip",
#         mimetype='application/zip'
#     )

# # Logout route
# @app.route('/logout')
# def logout():
#     session.pop('admin', None)
#     flash('You have been logged out.')
#     return redirect(url_for('index'))

# if __name__ == '__main__':
#     app.run(debug=True)