# syntax=docker/dockerfile:1.7
# Base image pinned by digest (written out in each FROM so scanners and Dependabot can read it).
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.txt .
# --require-hashes: every wheel must match the hash locked in requirements.txt
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-deps --require-hashes -r requirements.txt \
 && /opt/venv/bin/pip uninstall -y pip

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS runtime
LABEL org.opencontainers.image.source="https://github.com/Golovastik777/devsecops-platform" \
      org.opencontainers.image.title="kb-assistant"
# Pull Debian security fixes released after the base image was built, then remove the
# base image's pip: nothing is installed at runtime.
RUN apt-get update \
 && apt-get -y --no-install-recommends upgrade \
 && rm -rf /var/lib/apt/lists/* \
 && python -m pip uninstall -y pip \
 && groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app
COPY --from=build /opt/venv /opt/venv
COPY kb_assistant /app/kb_assistant
COPY kb /app/kb
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KB_DIR=/app/kb \
    METRICS_PORT=9100
WORKDIR /app
USER 10001:10001
EXPOSE 8080 9100
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.request; sys.exit(urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status != 200)"]
ENTRYPOINT ["uvicorn", "--factory", "kb_assistant.main:create_app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
