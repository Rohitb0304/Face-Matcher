import datetime
from werkzeug.security import generate_password_hash
import random
import json
from flask import session, flash, redirect, url_for, current_app
from flask_mail import Message
import jwt
from models import Admin, OTP, db
from flask_bcrypt import Bcrypt
import os
import re

bcrypt = Bcrypt()

# Function to load country codes from the static folder
def load_country_codes():
    try:
        # Path to the country_codes.json file in the static folder
        file_path = os.path.join(current_app.static_folder, 'CountryCodes.json')
        
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        flash("Country codes file not found!", "error")
        return []

class AdminAuth:
    @staticmethod
    def register_admin(data, mail):
        """Handle admin registration and send OTP."""
        name = data.get('name')  
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        mobile_number = data.get('mobile_number')
        country_code = data.get('country_code')

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords don't match!", "error")
            return redirect(url_for('register'))

        # Check if the username or email already exists
        if Admin.query.filter_by(username=username).first() or Admin.query.filter_by(email=email).first():
            flash("Username or Email already exists!", "error")
            return redirect(url_for('register'))

        # Email Validation
        if not email or '@' not in email:
            flash("Please enter a valid email address!", "error")
            return redirect(url_for('register'))

        # Validate country code
        country_codes = load_country_codes()
        if country_code not in [code['code'] for code in country_codes]:
            flash("Please select a valid country code!", "error")
            return redirect(url_for('register'))

        # Generate OTP
        otp = random.randint(100000, 999999)
        existing_otp = OTP.query.filter_by(email=email).first()
        if existing_otp:
            db.session.delete(existing_otp)
            db.session.commit()

        new_otp = OTP(email=email, otp=otp)
        db.session.add(new_otp)
        db.session.commit()

        # Create and send a styled OTP email
        msg = Message(subject="Your OTP for Registration", recipients=[email])
        msg.html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; color: #333333; background-color: #f4f4f4; padding: 20px; }}
                .email-container {{ background-color: #ffffff; padding: 20px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); }}
                .email-header {{ text-align: center; font-size: 24px; font-weight: bold; color: #4CAF50; }}
                .otp-code {{ font-size: 36px; font-weight: bold; color: #333333; text-align: center; padding: 20px; border: 2px solid #4CAF50; border-radius: 10px; background-color: #e8f5e9; }}
                .email-footer {{ text-align: center; margin-top: 20px; font-size: 14px; color: #888888; }}
                .footer-link {{ color: #4CAF50; text-decoration: none; }}
            </style>
        </head>
        <body>
            <div class="email-container">
                <div class="email-header">OTP for Registration</div>
                <p>Hello,</p>
                <p>Thank you for registering. To complete your registration, please use the following OTP:</p>
                <div class="otp-code">{otp}</div>
                <p>If you did not request this, please ignore this email.</p>
                <div class="email-footer">
                    <p>&copy; 2024 Your Website Name</p>
                    <p><a href="http://yourwebsite.com" class="footer-link">Visit our website</a></p>
                </div>
            </div>
        </body>
        </html>
        """

        mail.send(msg)

        # Store registration data in session for later use
        session['registration_data'] = {
            'name': name,
            'username': username,
            'email': email,
            'password': password,
            'mobile_number': mobile_number,
            'country_code': country_code
        }

        flash("OTP sent to email for verification.", "success")
        return redirect(url_for('verify_otp'))


    @staticmethod
    def verify_otp(otp):
        """Verify OTP and register admin."""
        data = session.get('registration_data')
        if not data:
            return {"success": False, "message": "Session expired. Please register again."}

        # Validate OTP
        stored_otp = OTP.query.filter_by(email=data['email'], otp=int(otp)).first()
        if not stored_otp:
            return {"success": False, "message": "Invalid OTP!"}

        # Hash password
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

        # Create the new admin record
        new_admin = Admin(
            name=data['name'],
            username=data['username'],
            email=data['email'],
            password_hash=hashed_password,
            mobile_number=data['mobile_number'],
            country_code=data['country_code']
        )
        db.session.add(new_admin)
        db.session.delete(stored_otp)
        db.session.commit()

        # Clear session data after registration
        session.pop('registration_data', None)

        return {"success": True, "message": "Registration successful!"}

    @staticmethod
    def login_admin(username, password):
        """Authenticate admin login."""
        # Check if username and password are provided
        if not username or not password:
            return {"success": False, "message": "Please enter both username and password to log in."}

        # Find admin by username
        admin = Admin.query.filter_by(username=username).first()

        if not admin:
            return {"success": False, "message": "Username not found. Please check your credentials and try again."}

        # Check if the provided password matches the stored hash
        if not bcrypt.check_password_hash(admin.password_hash, password):
            # Optional: Implement lockout mechanism for too many failed attempts
            return {"success": False, "message": "Incorrect password. Please try again or reset your password."}

        # Successful login
        return {"success": True, "message": f"Login successful! Welcome back, {admin.username}.", "admin_id": admin.id}


    
    @staticmethod
    def reset_password(token, password, confirm_password):
        """Reset the password using the token."""
        if password != confirm_password:
            return {"success": False, "message": "Passwords do not match!"}

        # Validate password complexity
        if len(password) < 8:
            return {"success": False, "message": "Password must be at least 8 characters long."}
        if not re.search(r"[A-Za-z]", password):
            return {"success": False, "message": "Password must include at least one letter."}
        if not re.search(r"\d", password):
            return {"success": False, "message": "Password must include at least one number."}

        try:
            # Decode the token
            decoded_token = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            email = decoded_token['email']

            # Fetch the user from the database
            admin = Admin.query.filter_by(email=email).first()
            if not admin:
                return {"success": False, "message": "User not found!"}

            # Hash the new password
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Update the password in the database
            admin.password_hash = hashed_password
            db.session.commit()

            return {"success": True, "message": "Your password has been successfully reset!"}

        except jwt.ExpiredSignatureError:
            return {"success": False, "message": "The reset link has expired."}
        except jwt.InvalidTokenError:
            return {"success": False, "message": "Invalid reset token."}
        except Exception as e:
            current_app.logger.error(f"Unexpected error during password reset: {e}")
            return {"success": False, "message": "An unexpected error occurred. Please try again later."}




    @staticmethod
    def send_reset_password_email(email, mail):
        """Send reset password email with token."""
        admin = Admin.query.filter_by(email=email).first()
        if not admin:
            return {"success": False, "message": "Email address not found. Please make sure you are registered!"}

        # Generate password reset token (valid for 1 hour)
        token = jwt.encode(
            {'email': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            current_app.config['SECRET_KEY'], algorithm='HS256'
        )

        # Create a reset password URL
        reset_url = url_for('reset_password', token=token, _external=True)

        # Create a reset password URL
        reset_url = url_for('reset_password', token=token, _external=True)

        # Send the email
        msg = Message(subject="Reset Your Password", recipients=[email])
        msg.html = f"""
        <p>To reset your password, click the link below:</p>
        <a href="{reset_url}">{reset_url}</a>
        <p>This link will remain active for 1 hour from the time it was generated. After that, it will expire, and you will need to request a new reset link.</p>
        <p>If you did not request this, please ignore this email.</p>
        """
        mail.send(msg)
        return {"success": True, "message": "A password reset link has been sent to your email address. Please check your inbox."}