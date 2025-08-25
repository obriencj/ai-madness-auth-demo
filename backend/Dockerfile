# Multi-stage build for AI Auth Backend
# Stage 1: Build the Python wheel
FROM python:3.11-slim as builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy package configuration files
COPY pyproject.toml setup.py ./
COPY ai_auth_backend/ ./ai_auth_backend/

# Create virtual environment and install build tools
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install build dependencies
RUN pip install --upgrade pip setuptools wheel build

# Build the wheel
RUN python -m build --wheel --outdir /wheels

# Stage 2: Production runtime
FROM python:3.11-slim as runtime

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash app

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy the built wheel
COPY --from=builder /wheels /wheels

# Install the wheel
RUN pip install --no-cache-dir /wheels/*.whl

# Copy application code
COPY wsgi.py ./

# Create necessary directories
RUN mkdir -p /app/logs && chown -R app:app /app

# Switch to non-root user
USER app

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Default command
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "wsgi:app"]

# The end.
