FROM python:3.10-slim

# Install system build dependencies required for compiling llama-cpp-python
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install python packages
COPY PhishingEmailDetection/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files into working directory
COPY PhishingEmailDetection/ .

# Set default port environment variable
ENV PORT=5000
EXPOSE ${PORT}

# Run production server using Gunicorn
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT} --workers 1 --threads 4 --timeout 300 app:app"]
