# # Use a base Python image
# FROM python:3.9-slim

# # Set environment variables
# ENV PYTHONDONTWRITEBYTECODE 1
# ENV PYTHONUNBUFFERED 1

# # Install necessary system dependencies
# RUN apt-get update && apt-get install -y \
#     build-essential \
#     cmake \
#     gfortran \
#     libopenblas-dev \
#     liblapack-dev \
#     libx11-dev \
#     libboost-all-dev \
#     libjpeg-dev \
#     zlib1g-dev \
#     && rm -rf /var/lib/apt/lists/*

# # Create and set the working directory
# WORKDIR /app

# # Copy the requirements file
# COPY requirements.txt /app/

# # Install Python dependencies (including using pre-built dlib wheels)
# RUN pip install --upgrade pip && \
#     pip install --no-cache-dir -r requirements.txt

# # Copy the application code
# COPY . /app/ 

# # Set the entry point (if applicable)
# CMD ["python", "app.py"]  # Replace with your app's entry point



# Stage 1: Build stage (dependencies)
FROM python:3.9-slim AS build-stage

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    gfortran \
    libopenblas-dev \
    liblapack-dev \
    libx11-dev \
    libboost-all-dev \
    libjpeg-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Stage 2: Final application image
FROM python:3.9-slim

WORKDIR /app
COPY --from=build-stage /app /app

# Copy application code
COPY . /app/

CMD ["python", "app.py"]
