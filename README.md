# Face-Matcher

This is a web application built using **Flask**, which matches faces uploaded by users with images from an event. The application uses **Face Recognition**, **Cloudinary** for image hosting, and **SQLAlchemy** for database management. The user can upload their face image, and the app will return matched faces from previously uploaded event images.

## Table of Contents

1. [Installation](#installation)
2. [Requirements](#requirements)
3. [Database Setup](#database-setup)
4. [Running the Application](#running-the-application)
5. [Development Workflow](#development-workflow)
6. [Environment Configuration](#environment-configuration)

---

## Installation

1. **Clone the Repository**

   Clone the project to your local machine:

   ```bash
   git clone https://github.com/Rohitb0304/Face-Matcher.git
   cd Face-Matcher
   ```

2. **Create a Virtual Environment**

   It's highly recommended to use a virtual environment for your project to manage dependencies.

   - For Windows:
     ```bash
     python -m venv venv
     venv\Scripts\activate
     ```

   - For macOS/Linux:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Install Dependencies**

   After activating the virtual environment, install all necessary dependencies from the `requirements.txt` file.

   ```bash
   pip install -r requirements.txt
   ```

---

## Requirements

Here is a list of required packages, which will be installed via `pip install -r requirements.txt`:

- **Flask**: A lightweight WSGI web application framework in Python.
- **Flask-SQLAlchemy**: SQLAlchemy support for Flask.
- **Flask-Migrate**: Database migration tool for Flask.
- **Flask-WTF**: Flask integration with WTForms for handling forms.
- **Face Recognition**: A simple face recognition library for Python.
- **Cloudinary**: For image storage and management in the cloud.
- **python-dotenv**: To load environment variables from a `.env` file.

The `requirements.txt` looks like this:

```txt
Flask==2.2.2
Flask-SQLAlchemy==2.5.1
Flask-Migrate==3.1.0
Flask-WTF==1.0.1
face-recognition==1.3.0
cloudinary==1.29.0
python-dotenv==0.21.0
```

---

## Database Setup

1. **Set Up the Database**

   You need to set up the database before running the app. Flask uses **SQLite** as the default database in this project. 

2. **Initialize Database**

   After installing dependencies and configuring your `.env` file (explained below), you can initialize your database by running the following command:

   ```bash
   flask db init
   ```

3. **Create the Database Migrations**

   Once the database is initialized, run the following command to generate migration scripts based on your models:

   ```bash
   flask db migrate -m "Initial migration"
   ```

4. **Apply Migrations**

   Finally, apply the migrations to create the necessary tables in the database:

   ```bash
   flask db upgrade
   ```

---

## Running the Application

Once the database is set up, you can start the application with the following command:

```bash
flask run
```

By default, the app will run on `http://127.0.0.1:5000`.

---

## Development Workflow

1. **Activating the Virtual Environment**

   Always activate your virtual environment before working on the project:

   - For Windows:
     ```bash
     venv\Scripts\activate
     ```

   - For macOS/Linux:
     ```bash
     source venv/bin/activate
     ```

2. **Running the Flask Application in Development Mode**

   To run the Flask application in development mode, which enables debugging and auto-reloading, use the following command:

   ```bash
   export FLASK_ENV=development
   flask run
   ```

   Alternatively, on Windows:

   ```bash
   set FLASK_ENV=development
   flask run
   ```

3. **Creating New Database Migrations**

   Whenever you make changes to your models (e.g., adding or removing columns), you need to create new migrations:

   ```bash
   flask db migrate -m "Your migration message"
   ```

4. **Applying Migrations**

   After generating a migration, apply it to update the database:

   ```bash
   flask db upgrade
   ```

5. **Seeding the Database**

   If you want to add test data or seed the database, you can write a custom script to add entries, or use a tool like `Flask-Script` or `Flask-Shell` to interact with the database.

---

## Environment Configuration

1. **Setting up `.env` file**

   You need to create a `.env` file in the project’s root directory to configure environment variables such as **Cloudinary credentials** and **Flask secret key**. Here’s an example `.env` file:

   ```plaintext
   FLASK_APP=app.py
   FLASK_SECRET_KEY=your_flask_secret_key
   CLOUDINARY_URL=cloudinary://<your-cloud-name>:<your-api-key>@<your-api-secret>
   ```

   Replace `<your-cloud-name>`, `<your-api-key>`, and `<your-api-secret>` with the actual credentials you get from Cloudinary.

2. **Loading the Environment Variables**

   The environment variables in the `.env` file will be automatically loaded using the **python-dotenv** package.

---

## .gitignore

Make sure you don't commit sensitive files like `.env` to your version control system (e.g., Git). You should have a `.gitignore` file in the root directory with the following content:

```plaintext
*.pyc
__pycache__/
*.env
instance/
.venv/
*.db
*.sqlite3
```

This will prevent files like `.env` from being uploaded to GitHub or other repositories.

---
