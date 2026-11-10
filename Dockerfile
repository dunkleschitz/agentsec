# agentsec CLI image. Stdlib-only runtime; no telemetry; runs as a non-root user.
# Build:  docker build -t ghcr.io/dunkleschitz/agentsec:local .
# Run:    docker run --rm -v "$PWD:/work:ro" ghcr.io/dunkleschitz/agentsec:local mcpposture /work/mcp.json
FROM python:3.12-slim

LABEL org.opencontainers.image.title="agentsec" \
      org.opencontainers.image.description="Offline, stdlib-only Python CLIs that scan AI agents for prompt injection, MCP tool poisoning, SSRF, and secret leaks." \
      org.opencontainers.image.source="https://github.com/dunkleschitz/agentsec" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.url="https://dunkleschitz.github.io/agentsec/"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Non-root user (uid 1000) — no login shell, no home secrets.
RUN groupadd --gid 1000 agentsec \
 && useradd --uid 1000 --gid agentsec --create-home --home-dir /home/agentsec \
            --shell /usr/sbin/nologin agentsec \
 && mkdir -p /src /work \
 && chown agentsec:agentsec /work

WORKDIR /src

# Copy only what the build needs to install the package.
COPY pyproject.toml setup.py MANIFEST.in README.md LICENSE ./
COPY agentsec ./agentsec
COPY tools ./tools

RUN python -m pip install --no-cache-dir --upgrade pip \
 && python -m pip install --no-cache-dir . \
 && rm -rf /src /root/.cache /tmp/pip-* \
 && mkdir -p /src

WORKDIR /work
USER agentsec

# Default: show CLI help. Override with a tool name and paths, e.g. mcpposture /work/mcp.json
ENTRYPOINT ["agentsec"]
CMD ["--help"]
