# Bastion — Docker image for local evaluation
#
# Runs in demo mode by default (no root, no nftables applied).
# For live mode, pass -e BASTION_SECRET_KEY=<value> and ensure
# the container has CAP_NET_ADMIN with access to the host network namespace.
#
# Build:   docker build -t bastion .
# Run:     docker run --rm -p 8443:8443 bastion

# Pinned digest for python:3.12-slim to prevent supply-chain attacks
# via floating tag. Update by running: docker pull python:3.12-slim
# then: docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim
FROM python:3.12-slim@sha256:af4e85f1f62feee3f3e5e8ef94e6e72a19deaaee7e38e0e0bfc86a953467c11f

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