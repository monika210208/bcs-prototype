# -------------------------------------------------------------
# Dockerfile for Blockchain Cloud Storage (BCS) Prototype
# Multi-stage, secure, zero-dependency lightweight container
# -------------------------------------------------------------
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

# Create app directory
WORKDIR /app

# Copy application files
COPY . /app

# Ensure non-root user for security best practices
RUN groupadd -r bcsuser && useradd -r -g bcsuser bcsuser && \
    mkdir -p /app/storage /app/frontend && \
    chown -R bcsuser:bcsuser /app

USER bcsuser

# Expose default application port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:' + str(__import__('os').environ.get('PORT', 8000)) + '/api/health')" || exit 1

# Start the full-stack server
CMD ["python3", "server.py"]
