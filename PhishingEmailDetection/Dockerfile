FROM python:3.10-slim

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV HF_HUB_DISABLE_SYMLINKS_WARNING=1
ENV PORT=10000

# Copy requirements and install python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install pre-compiled CPU binary wheel for llama-cpp-python
RUN pip install llama-cpp-python --only-binary llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu --no-cache-dir

# Pre-download default SmolLM2 model during build so website scans execute instantly
RUN python -c "from huggingface_hub import hf_hub_download; hf_hub_download(repo_id='bartowski/SmolLM2-135M-Instruct-GGUF', filename='SmolLM2-135M-Instruct-Q4_K_M.gguf')"

# Copy application files
COPY . .

EXPOSE 10000

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-10000} --workers 1 --threads 2 --timeout 300 app:app"]
