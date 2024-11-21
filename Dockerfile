# Base image with Python
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory
WORKDIR /app

# Copy requirements file
COPY requirements.txt /app/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . /app/

# Expose the port the app runs on
EXPOSE 5000

# Set Flask environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=development

# Run migrations and the app
CMD ["bash", "-c", "flask db init && flask db migrate && flask db upgrade && python app.py"]