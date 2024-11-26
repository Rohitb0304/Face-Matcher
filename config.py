import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = 'sqlite:///app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    CLOUD_NAME = os.getenv("CLOUD_NAME")
    API_KEY = os.getenv("API_KEY")
    API_SECRET = os.getenv("API_SECRET")
    MAX_SIZE_MB = 20 
