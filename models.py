from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Boolean
from datetime import datetime

db = SQLAlchemy()

from sqlalchemy import Integer, String, Boolean, DateTime
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Admin(db.Model):
    __tablename__ = 'admins'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    mobile_number = db.Column(db.String(15), nullable=True)  # Store mobile number as string
    country_code = db.Column(db.String(5), nullable=True)  # Store country code (e.g., "+1", "+44", etc.)
    password_hash = db.Column(db.String(200), nullable=True)  # Nullable for Google users
    google_id = db.Column(db.String(200), nullable=True, unique=True)
    is_verified = db.Column(Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship with Event model
    events = db.relationship('Event', backref='admin', lazy=True)
    
    def __repr__(self):
        return f"<Admin {self.username}, {self.email}, Verified: {self.is_verified}, Mobile: {self.mobile_number}>"

class OTP(db.Model):
    __tablename__ = 'otps'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    otp = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<OTP for {self.email}, OTP: {self.otp}, Created At: {self.created_at}>"

class Event(db.Model):
    __tablename__ = 'events'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, nullable=False)
    unique_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)
    
    def __repr__(self):
        return f"<Event {self.name}, {self.date}, Admin ID: {self.admin_id}>"

class Image(db.Model):
    __tablename__ = 'images'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    cloudinary_url = db.Column(db.String(255), nullable=False)
    public_id = db.Column(db.String(255), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    is_matched = db.Column(Boolean, default=False, nullable=False)
    
    # Relationship with Event model
    event = db.relationship('Event', backref=db.backref('images', lazy=True))
    
    def __repr__(self):
        return f"<Image {self.filename}, Event ID: {self.event_id}, Matched: {self.is_matched}>"