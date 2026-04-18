# --- Builder Stage ---
FROM gcc:12 AS builder
RUN apt-get update && apt-get install -y cmake make libpcap-dev
WORKDIR /app
COPY . .
RUN mkdir -p build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc) && \
    # Create a unified binary name for the next stage to be bulletproof
    (cp traffic_engine ../engine_bin 2>/dev/null || cp mock_engine ../engine_bin)

# --- Runtime Stage ---
FROM python:3.9-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libcap2-bin \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir gunicorn eventlet && \
    pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY scripts/ /app/scripts/
COPY templates/ /app/templates/
COPY --from=builder /app/engine_bin /app/traffic_engine

# Setup permissions and non-root user
RUN mkdir -p /app/uploads && \
    chmod +x /app/traffic_engine && \
    chmod +x /app/docker-entrypoint.sh && \
    setcap cap_net_raw,cap_net_admin=eip /app/traffic_engine 2>/dev/null || true && \
    useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

USER appuser

ENV ANALYZER_BIN=/app/traffic_engine
ENV UPLOAD_FOLDER=/app/uploads
ENV PORT=5000
ENV FLASK_ENV=production

EXPOSE 5000 8080

ENTRYPOINT ["/app/docker-entrypoint.sh"]

EXPOSE 5000

# Use gunicorn with eventlet for WebSocket/SocketIO production support
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:5000", "--access-logfile", "-", "scripts.dashboard:app"]
