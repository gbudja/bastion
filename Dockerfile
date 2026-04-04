# Bastion — Docker image for local evaluation
#
# Runs in demo mode by default (no root, no nftables applied).
# For live mode, pass -e BASTION_SECRET_KEY=<value> and ensure
# the container has CAP_NET_ADMIN with access to the host network namespace.
#
# Build:   docker build -t bastion .
# Run:     docker run --rm -p 8443:8443 bastion

FROM python:3.12-slim

# Security: run as non-root
RUN groupadd --gid 1001 bastion \
    && useradd --uid 1001 --gid bastion --no-create-home --shell /sbin/nologin bastion

WORKDIR /app

# Install Python dependencies before copying source (better layer caching)
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e ".[dev]" 2>/dev/null || pip install --no-cache-dir -e . \
    && pip install --no-cache-dir flask flask-socketio pyyaml psutil click rich eventlet

# Copy application source
COPY bastion/ ./bastion/
COPY config/ ./config/

# Switch to non-root user
USER bastion

EXPOSE 8443

# Default: demo mode (safe, no root required)
CMD ["bastion", "start", "--demo", "--host", "0.0.0.0", "--port", "8443"]
