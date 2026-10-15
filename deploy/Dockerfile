# ---------------------------------------------------------------------------
# Stage 1: Build & Dependency Wheel Isolation
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: Minimal Hardened Production Runner (UID 10001:10001)
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runner

WORKDIR /app

# Enforce non-root execution (EU AI Act & CIS Benchmark compliance)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser

# Copy installed Python packages from builder stage
COPY --from=builder /root/.local /home/appuser/.local
ENV PATH=/home/appuser/.local/bin:$PATH

# Copy application code
COPY --chown=appuser:appgroup app /app/app
COPY --chown=appuser:appgroup data /app/data

# Create directory for runtime Chroma storage and audit logs
RUN mkdir -p /app/chroma_db && chown -R appuser:appgroup /app

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/healthz || exit 1

ENTRYPOINT ["uvicorn", "app.main.py:app", "--host", "0.0.0.0", "--port", "8000"]