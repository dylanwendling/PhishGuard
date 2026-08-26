FROM python:3.10-slim

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install pre-compiled CPU binary wheel for llama-cpp-python (fast, avoids compiling C++ from source)
RUN pip install llama-cpp-python --only-binary llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu --no-cache-dir

# Copy application files
COPY . .

# Set default port environment variable
ENV PORT=5000
EXPOSE ${PORT}

# Run production server using Gunicorn
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT} --workers 1 --threads 4 --timeout 300 app:app"]
