# LIBRARY IMPORTS
import hashlib
import random
import string
import io
import base64
import json
import zipfile
import os
from io import BytesIO
import PIL
import sys
import bcrypt
import jwt
import secrets
import re
import requests
import qrcode
import cloudinary
import cloudinary.uploader
from flask import Flask, jsonify, render_template, request, redirect, send_file, url_for, session, flash, Response, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import db, Admin, Event, Image
from config import Config
from PIL import Image as PILImage
from datetime import datetime
import face_recognition
from werkzeug.exceptions import RequestEntityTooLarge
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail
from tempfile import NamedTemporaryFile
import shutil
import logging
logging.basicConfig(level=logging.DEBUG)
from admin_auth import AdminAuth
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.config.from_object(Config)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Adjust if needed
app.config['SECRET_KEY'] = '6633b749e8afcc73149c758c29926fc973c31109bdc0f1ce11942c690a025d09'

# Initialize CSRF protection
csrf = CSRFProtect(app)

bcrypt = Bcrypt(app)

# Initialize database and migration
db.init_app(app)
migrate = Migrate(app, db)

MAX_SIZE_MB = 10
app.config['MAX_CONTENT_LENGTH'] = 30 * 1024 * 1024  # 30MB
MAX_PIXELS = (1920, 1080)
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}


@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large_error(error):
    flash("The file is too large. Please upload a smaller file.", 'error')
    return redirect(url_for('user_upload'))


def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

cloudinary.config(
    cloud_name=Config.CLOUD_NAME,
    api_key=Config.API_KEY,
    api_secret=Config.API_SECRET
)

# Route to display all events
@app.route('/')
def index():
    events = Event.query.all()  # Fetch all events from the database
    return render_template('home.html', events=events)

@app.route('/generate_qr_code/<string:event_id>')
def generate_qr_code(event_id):
    # Fetch event by its unique ID
    event = Event.query.filter_by(unique_id=event_id).first_or_404()

    # Construct the full event URL
    event_url = f"{EVENT_URL_PREFIX}/{event.unique_id}"

    # Generate QR code based on the full event URL
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(event_url)  # Use the full event URL in the QR code
    qr.make(fit=True)

    img = qr.make_image(fill="black", back_color="white")

    # Save QR code image to a BytesIO object
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)

    return Response(img_io, mimetype='image/png')


# Image Hashing Function
def image_hash(image_data):
    """Generate a hash for the image to identify duplicates."""
    img = PILImage.open(io.BytesIO(image_data))
    img = img.convert("RGB")
    img.thumbnail((100, 100))
    hash_value = hashlib.md5(img.tobytes()).hexdigest()
    return hash_value

# Helper function to generate a unique event ID
def generate_unique_event_id(event_name):
    unique_event_id = f"{event_name.lower().replace(' ', '-')}-{random.randint(1000, 9999)}"
    
    # Ensure the event ID is unique by checking the database
    while Event.query.filter_by(unique_id=unique_event_id).first():
        unique_event_id = f"{event_name.lower().replace(' ', '-')}-{random.randint(1000, 9999)}"
    
    return unique_event_id

mail = Mail(app)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Pass form data to AdminAuth for processing
        result = AdminAuth.register_admin(request.form, mail)  # Use current_app.mail to access the Mail instance
        
        if result:
            # If the result is a redirect or something else, handle the response accordingly
            return result
        
        # If there is an issue, flash the error message and stay on the register page
        flash("An error occurred during registration. Please try again.", 'error')
        return redirect(url_for('register'))

    # Load country codes from a JSON file located in the static folder
    try:
        with open('static/CountryCodes.json') as file:
            country_codes = json.load(file)
    except FileNotFoundError:
        flash("Country codes file not found!", 'error')
        country_codes = []

    return render_template('register.html', country_codes=country_codes)


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        
        # Verify OTP using AdminAuth
        result = AdminAuth.verify_otp(otp)

        if result['success']:
            flash(result['message'], 'success')  # Display success message
            return redirect(url_for('login'))  # Redirect to login page
        else:
            flash(result['message'], 'error')  # Display error message
            return redirect(url_for('verify_otp'))  # Stay on the verify OTP page

    return render_template('verify_otp.html')



# Admin login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate if username and password are provided
        if not username or not password:
            flash("Please enter both username and password to log in.", "error")
            return redirect(url_for('login'))

        # Authenticate login using AdminAuth
        result = AdminAuth.login_admin(username, password)

        if result['success']:
            # Successful login
            session['admin'] = result['admin_id']  # Store admin ID in the session
            flash(result['message'], 'success')   # Flash a success message
            return redirect(url_for('dashboard'))  # Redirect to dashboard

        # Flash the error message returned by the login function
        flash(result['message'], 'error')
        return redirect(url_for('login'))  # Redirect back to the login page

    # Render login page for GET requests
    return render_template('login.html')


# Admin dashboard route
@app.route('/dashboard')
def dashboard():
    # Check if the admin is logged in
    if not session.get('admin'):
        return redirect(url_for('login'))

    # Get the admin_id from the session (assuming it stores only admin_id)
    admin_id = session['admin']

    # Fetch the admin object from the database using the admin_id
    admin = Admin.query.get(admin_id)  # Assuming you have an Admin model

    # Fetch events associated with this admin
    events = Event.query.filter_by(admin_id=admin_id).all()

    # Pass both admin and events to the template
    return render_template('dashboard.html', events=events, admin=admin)

# Load the URL prefix from the environment variable
EVENT_URL_PREFIX = os.getenv("EVENT_URL_PREFIX", "https://yourdomain.com/event/")  # Default to a fallback URL

# Manage event route
@app.route('/manage_event/<string:event_id>', methods=['GET', 'POST'])
def manage_event(event_id):
    # Fetch event by its unique ID
    event = Event.query.filter_by(unique_id=event_id).first_or_404()
    images = Image.query.filter_by(event_id=event.id).all()

    # Construct the full event URL using the prefix from .env
    event_url = f"{EVENT_URL_PREFIX}{event.unique_id}"

    if request.method == 'POST':
        # Handle the form submission for event details update
        event_name = request.form['event_name']
        event_date = request.form['event_date']
        
        try:
            # Parse the event date (handle the date format)
            event_date_obj = datetime.strptime(event_date, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.', 'danger')
            return redirect(url_for('manage_event', event_id=event.unique_id))
        
        # Update the event details in the database
        event.name = event_name
        event.date = event_date_obj
        db.session.commit()  # Commit changes to the database

        # Flash a success message after update
        flash('Event details updated successfully!', 'success')
        
        # Redirect to the same page to reflect changes
        return redirect(url_for('manage_event', event_id=event.unique_id))

    # Render the template with the event and images data, including the generated event URL
    return render_template('manage_event.html', event=event, images=images, event_url=event_url)



# User image upload route
@app.route('/user_upload', methods=['GET', 'POST'])
def user_upload():
    if request.method == 'GET' and 'event_id' in request.args:
        event_id = request.args.get('event_id')
        event = Event.query.filter_by(unique_id=event_id).first()

        if not event:
            flash("Event not found. Please check the Event ID and try again.", 'error')
            return redirect(url_for('user_upload'))

        return render_template('user_upload.html', event=event)

    if request.method == 'POST' and 'event_id' in request.form:
        event_id = request.form.get('event_id')
        event = Event.query.filter_by(unique_id=event_id).first_or_404()

        # CSRF token is automatically validated by Flask-WTF during POST request

        # Get the base64 image data sent from the frontend (webcam capture)
        image_data = request.form.get('image')

        # Check for image size before processing
        if image_data:
            image_size = len(image_data)
            if image_size > MAX_SIZE_MB * 1024 * 1024:
                flash("The image is too large. Please upload a smaller image.", "error")
                return redirect(url_for('user_upload', event_id=event_id))

        if not image_data:
            flash('No image data found in the request.', 'error')
            return redirect(url_for('user_upload', event_id=event_id))

        # Remove base64 prefix (data:image/png;base64,)
        try:
            image_data = image_data.split(",")[1]  # Strip out the base64 prefix
        except IndexError:
            flash('Invalid image data format.', 'error')
            return redirect(url_for('user_upload', event_id=event_id))

        try:
            # Decode the image from base64
            img_bytes = base64.b64decode(image_data)
            img = PILImage.open(io.BytesIO(img_bytes))  # Open the image from bytes

            # Verify the image immediately after opening
            img.verify()  # Verifies if the image is corrupted
            img = PILImage.open(io.BytesIO(img_bytes))  # Reopen the image after verification

            # Resize the image to reduce its size while keeping the aspect ratio
            img.thumbnail(MAX_PIXELS)

        except Exception as e:
            flash(f"Error processing image: {str(e)}. Please upload a valid image.", 'error')
            return redirect(url_for('user_upload', event_id=event_id))

        # Perform face recognition (this will be handled similarly to how you've implemented it)
        try:
            uploaded_image = face_recognition.load_image_file(io.BytesIO(img_bytes))
            uploaded_encodings = face_recognition.face_encodings(uploaded_image)

            if not uploaded_encodings:
                flash('No face found in the captured image. Please try again with a different photo.', 'error')
                return redirect(url_for('user_upload', event_id=event_id))

            # Use the first face encoding if multiple faces are detected
            uploaded_encoding = uploaded_encodings[0]
            matched_images = []

            # Compare with faces in the event's images stored in the database
            for db_image in Image.query.filter_by(event_id=event.id).all():
                try:
                    response = requests.get(db_image.cloudinary_url)
                    response.raise_for_status()

                    db_image_file = face_recognition.load_image_file(io.BytesIO(response.content))
                    db_encodings = face_recognition.face_encodings(db_image_file)

                    # Ensure there is at least one face encoding in the database image
                    if db_encodings:
                        # Compare each face encoding from the event image
                        for db_encoding in db_encodings:
                            # Compare faces with a stricter tolerance for better accuracy
                            is_match = face_recognition.compare_faces([db_encoding], uploaded_encoding, tolerance=0.5)[0]
                            if is_match:
                                matched_images.append(db_image)
                                break  # Stop further comparison once a match is found

                except requests.exceptions.RequestException as e:
                    print(f"Error fetching image from Cloudinary URL: {db_image.cloudinary_url}. Error: {e}")
                    continue
                except PIL.UnidentifiedImageError as e:
                    print(f"Cannot identify image at {db_image.cloudinary_url}. Error: {e}")
                    continue
                except Exception as e:
                    print(f"Error processing image: {str(e)}")
                    continue

            if not matched_images:
                flash('No matched faces found in the event images. Please try another photo.', 'info')

            return render_template('user_results.html', matched_images=matched_images, event=event)

        except Exception as e:
            flash(f"Error processing face recognition: {str(e)}. Please try again with a valid image.", 'error')
            return redirect(url_for('user_upload', event_id=event_id))

    return render_template('user_upload.html')



@app.route('/admin_upload/<string:event_id>', methods=['POST'])
def admin_upload(event_id):
    try:
        event = Event.query.filter_by(unique_id=event_id).first_or_404()
        admin = Admin.query.get(session['admin'])

        if 'files' not in request.files:
            flash('No files were uploaded.', 'error')
            logging.debug("No files uploaded.")
            return redirect(url_for('manage_event', event_id=event.unique_id))

        files = request.files.getlist('files')
        if not files:
            flash('No files selected for upload.', 'error')
            logging.debug("No files selected.")
            return redirect(url_for('manage_event', event_id=event.unique_id))

        total_files = len(files)
        uploaded_files = 0  # Keep track of uploaded files
        logging.debug(f"Total files to upload: {total_files}")

        for file in files:
            if file.filename == '':
                flash('Empty file detected, skipping.', 'error')
                logging.debug(f"Empty file detected: {file}")
                continue

            filename = secure_filename(file.filename)
            if not allowed_file(filename):
                flash(f"File {filename} is not an allowed type. Only JPG, JPEG, PNG are allowed.", 'error')
                logging.debug(f"Invalid file type: {filename}")
                continue

            file.seek(0)  # Check file size
            if len(file.read()) > MAX_SIZE_MB * 1024 * 1024:
                flash(f"File {filename} exceeds the {MAX_SIZE_MB}MB size limit.", 'error')
                logging.debug(f"File {filename} exceeds size limit.")
                continue

            file.seek(0)  # Reset the file pointer after checking size

            with NamedTemporaryFile(delete=False, suffix='.jpg') as tmp_file:
                tmp_file.write(file.read())
                tmp_file_path = tmp_file.name

            try:
                # Upload the image to Cloudinary
                upload_result = cloudinary.uploader.upload(
                    tmp_file_path,
                    folder=f"{admin.username}_{event.unique_id}",
                    public_id=f"{admin.username}_{event.unique_id}_{random.randint(1000, 9999)}",
                    use_filename=True,
                    unique_filename=True
                )

                # Extract Cloudinary response details
                public_id = upload_result['public_id']
                secure_url = upload_result['secure_url']

                # Insert the image record into the database
                new_image = Image(
                    filename=filename,
                    cloudinary_url=secure_url,
                    public_id=public_id,
                    event_id=event.id
                )
                db.session.add(new_image)
                db.session.commit()

                uploaded_files += 1  # Increment the counter for successfully uploaded files

                # Provide feedback for each uploaded file
                flash(f"File {filename} uploaded successfully!", 'success')
                logging.debug(f"File {filename} uploaded successfully!")

            except Exception as e:
                db.session.rollback()  # Rollback in case of error
                flash(f"Error during upload of {filename}: {str(e)}", 'error')
                logging.debug(f"Error during upload of {filename}: {str(e)}")

            finally:
                os.remove(tmp_file_path)  # Clean up temporary file

            # Simulate progress feedback
            progress_percentage = (uploaded_files / total_files) * 100
            flash(f"Upload progress: {int(progress_percentage)}% completed.", 'info')

        # Final message once all files are uploaded
        flash(f"Successfully uploaded {uploaded_files} out of {total_files} images!", 'success')

        return redirect(url_for('manage_event', event_id=event.unique_id))

    except Exception as e:
        db.session.rollback()  # Rollback on unexpected error
        flash(f"An unexpected error occurred: {str(e)}", 'error')
        logging.debug(f"Unexpected error: {str(e)}")
        return redirect(url_for('manage_event', event_id=event_id))



@app.route('/save_image', methods=['POST'])
def save_image():
    try:
        data = request.get_json()
        image_url = data['imageUrl']
        public_id = data['publicId']
        event_id = data['eventId']

        # Ensure the event exists
        event = Event.query.filter_by(unique_id=event_id).first_or_404()

        # Save the image details to the database
        new_image = Image(
            filename=public_id,  # Use public_id or the original filename
            cloudinary_url=image_url,
            public_id=public_id,
            event_id=event.id
        )

        db.session.add(new_image)
        db.session.commit()

        return jsonify(success=True)

    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, error=str(e))

@app.route('/delete_image/<int:image_id>', methods=['POST'])
def delete_image(image_id):
    image = Image.query.get_or_404(image_id)
    try:
        # Delete from Cloudinary
        cloudinary.uploader.destroy(image.public_id)
        # Delete from database
        db.session.delete(image)
        db.session.commit()
        flash('Image deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting image: {e}', 'danger')

    return redirect(request.referrer)


@app.route('/events')
def events():
    events = Event.query.all()  # Fetch all events from the database
    return render_template('events.html', events=events)

# Create event route
@app.route('/create_event', methods=['GET', 'POST'])
def create_event():
    if not session.get('admin'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        event_name = request.form['event_name']
        event_date_str = request.form['event_date']

        try:
            event_date = datetime.strptime(event_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.")
            return redirect(url_for('create_event'))

        unique_event_id = generate_unique_event_id(event_name)

        admin_id = session['admin']
        new_event = Event(name=event_name, date=event_date, admin_id=admin_id, unique_id=unique_event_id)
        db.session.add(new_event)
        db.session.commit()

        flash("Event created successfully!")
        return redirect(url_for('dashboard'))

    return render_template('create_event.html')

# Route to download individual image
@app.route('/download_image/<int:image_id>', methods=['GET'])
def download_image(image_id):
    # Fetch the image from the database
    image = Image.query.get_or_404(image_id)
    
    try:
        # Send the file directly from Cloudinary
        response = requests.get(image.cloudinary_url)
        image_data = io.BytesIO(response.content)

        # Serve the file to the user for download
        return send_file(
            image_data,
            as_attachment=True,
            download_name=image.filename,
            mimetype='image/jpeg'
        )

    except Exception as e:
        flash(f'Error downloading image: {e}', 'danger')
        return redirect(request.referrer)

@app.route('/download_images_zip/<string:event_id>', methods=['GET'])
def download_images_zip(event_id):
    # Fetch the event from the database using the unique event ID
    event = Event.query.filter_by(unique_id=event_id).first_or_404()

    # Get all matched images for the event (only images that have `is_matched=True`)
    matched_images = Image.query.filter_by(event_id=event.id, is_matched=True).all()

    if not matched_images:
        flash(f'No matched images found for this event.', 'warning')
        return redirect(request.referrer)  # Redirect the user to the previous page or event page

    # Create a BytesIO object to store the zip file in memory
    zip_io = BytesIO()

    with zipfile.ZipFile(zip_io, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for image in matched_images:
            # Download the image from Cloudinary
            response = requests.get(image.cloudinary_url)

            if response.status_code == 200:
                # Write each matched image to the zip file using the filename as the archive name
                zip_file.writestr(image.filename, response.content)
            else:
                # Log an error or handle the case where the image can't be fetched
                flash(f"Failed to fetch image: {image.filename}", 'error')

    # Rewind the BytesIO object to the beginning so it can be read
    zip_io.seek(0)

    # Serve the zip file to the user for download
    return send_file(
        zip_io,
        as_attachment=True,
        download_name=f"{event.name}_{event_id}_matched_images.zip",
        mimetype='application/zip'
    )



@app.route('/delete_event/<event_id>', methods=['POST'])
def delete_event(event_id):
    # Find the event by unique_id
    event = Event.query.filter_by(unique_id=event_id).first()
    
    if event:
        db.session.delete(event)
        db.session.commit()
        flash('Event deleted successfully!', 'success')
    else:
        flash('Event not found!', 'danger')
    
    return redirect(url_for('dashboard'))

# Logout route
@app.route('/logout')
def logout():
    session.pop('admin', None)
    flash('You have been logged out.')
    return redirect(url_for('index'))




logger = logging.getLogger('gunicorn.error')
logger.addHandler(logging.StreamHandler(sys.stdout))
logger.setLevel(logging.DEBUG)

# Route to display the profile page
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    # Check if the admin is logged in
    if not session.get('admin'):
        return redirect(url_for('login'))

    # Get the admin details from the database
    admin_id = session['admin']
    admin = Admin.query.get(admin_id)

    if request.method == 'POST':
        # Update the profile information
        new_username = request.form.get('username')
        new_email = request.form.get('email')

        # Ensure the username or email doesn't already exist
        if new_username != admin.username and Admin.query.filter_by(username=new_username).first():
            flash('Username already taken.', 'error')
            return redirect(url_for('profile'))

        if new_email != admin.email and Admin.query.filter_by(email=new_email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('profile'))

        # Update details in the database
        admin.username = new_username
        admin.email = new_email
        db.session.commit()

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', admin=admin)

# Route to display the password change settings
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    # Check if the admin is logged in
    if not session.get('admin'):
        return redirect(url_for('login'))

    admin_id = session['admin']
    admin = Admin.query.get(admin_id)

    if request.method == 'POST':
        # Get the data from the form
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Verify the current password
        if not check_password_hash(admin.password_hash, current_password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('settings'))

        # Check if new password and confirmation match
        if new_password != confirm_password:
            flash("New password and confirmation don't match.", 'error')
            return redirect(url_for('settings'))

        # Hash the new password and update it
        hashed_new_password = generate_password_hash(new_password)
        admin.password_hash = hashed_new_password
        db.session.commit()

        flash('Password updated successfully!', 'success')
        return redirect(url_for('settings'))

    return render_template('settings.html', admin=admin)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        # Send reset email and get the result
        result = AdminAuth.send_reset_password_email(email, mail)

        if result['success']:
            flash("Success! A password reset link has been sent to your email address. Please check your inbox.", "success")
        else:
            flash(result['message'], "error")  # Flash the error message if email sending fails

        # Render the same forgot password page so users see the message
        return redirect(url_for('forgot_password'))
    
    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Decode the token to retrieve the email
        data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        email = data['email']
    except jwt.ExpiredSignatureError:
        flash("The reset link has expired. Please request a new one.", "error")
        return redirect(url_for('forgot_password'))
    except jwt.InvalidTokenError:
        flash("Invalid reset link. Please request a new one.", "error")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for('reset_password', token=token))

        # Validate password complexity
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
            return redirect(url_for('reset_password', token=token))
        if not re.search(r"[A-Za-z]", password):
            flash("Password must include at least one letter.", "error")
            return redirect(url_for('reset_password', token=token))
        if not re.search(r"\d", password):
            flash("Password must include at least one number.", "error")
            return redirect(url_for('reset_password', token=token))

        # Hash the password
        try:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        except Exception as e:
            current_app.logger.error(f"Password hashing failed: {e}")
            flash("An unexpected error occurred while processing your password. Please try again.", "error")
            return redirect(url_for('reset_password', token=token))

        # Update the admin's password
        admin = Admin.query.filter_by(email=email).first()
        if admin:
            admin.password_hash = hashed_password
            try:
                db.session.commit()
                flash("Your password has been successfully reset! Redirecting to the login page in 5 seconds...", "success")
                return redirect(url_for('reset_password_success'))
            except Exception as e:
                flash("An error occurred while updating the password. Please try again.", "error")
                current_app.logger.error(f"Error resetting password: {e}")
                return redirect(url_for('reset_password', token=token))
        else:
            flash("User not found.", "error")

    return render_template('reset_password.html', token=token)


@app.route('/reset_password_success')
def reset_password_success():
    return render_template('reset_success.html')




def generate_nonce(length=32):
    """
    Generate a cryptographically secure nonce (random string) of a specified length.
    The nonce is used to prevent replay attacks and should be unique per request.
    """
    # Create a secure random string of letters and digits for the nonce
    alphabet = string.ascii_letters + string.digits
    nonce = ''.join(secrets.choice(alphabet) for _ in range(length))
    return nonce

def generate_state(length=32):
    """
    Generate a cryptographically secure state parameter of a specified length.
    The state is used to prevent CSRF attacks and should be unique per request.
    """
    # Create a secure random string for the state parameter
    alphabet = string.ascii_letters + string.digits
    state = ''.join(secrets.choice(alphabet) for _ in range(length))
    return state


if __name__ == '__main__':
    app.run(debug=True)