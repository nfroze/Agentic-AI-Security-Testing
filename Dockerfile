# Stage 1: Builder
FROM python:3.11-slim AS builder

WORKDIR /build

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY pyproject.toml .

# Stage 2: Runtime
FROM python:3.11-slim AS runtime

LABEL maintainer="Noah Frost <noah@noahfrost.co.uk>"
LABEL version="0.1.0"
LABEL description="Agentic AI Security Testing Platform - Backend API"

# Security: Create non-root user with limited privileges
RUN groupadd -r appuser && \
    useradd -r -g appuser -d /app -s /sbin/nologin -c "Docker app user" appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code from builder
COPY --from=builder /build/src ./src
COPY --from=builder /build/pyproject.toml .

# Copy payload files
COPY payloads/ ./payloads/

# Set ownership to appuser
RUN chown -R appuser:appuser /app && \
    find /app -type f -executable ! -path "*/.*" -exec chmod u+x {} \;

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/')" || exit 1

# Expose API port
EXPOSE 8000

# Read-only rootfs compatible entrypoint
# Uses /tmp for temporary files (mounted as tmpfs in docker-compose)
CMD ["python", "-m", "uvicorn", "agentic_security.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
