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
    && useradd --uid 1001 --gid bastion --no-create-home --shell /usr/sbin/nologin bastion

WORKDIR /app

# Copy project files first (required for proper install)
COPY pyproject.toml ./
COPY bastion/ ./bastion/
COPY config/ ./config/

# Install project (uses pyproject.toml dependencies)
RUN pip install --no-cache-dir .

# Switch to non-root user
USER bastion

EXPOSE 8443

# Default: demo mode (safe, no root required)
CMD ["bastion", "start", "--demo", "--host", "0.0.0.0", "--port", "8443"]