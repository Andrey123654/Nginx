FROM ubuntu:26.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl fonts-dejavu-core python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 nginxscope \
    && useradd --system --uid 10001 --gid nginxscope --home /app --shell /usr/sbin/nologin nginxscope

WORKDIR /app
COPY requirements.txt ./
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY --chown=nginxscope:nginxscope audit.py ./
COPY --chown=nginxscope:nginxscope web ./web
USER 10001:10001
ENV PATH="/opt/venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 MAX_UPLOAD_BYTES=5242880 PUBLIC_ORIGIN=http://127.0.0.1:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["curl", "--fail", "http://127.0.0.1:8080/healthz"]
CMD ["uvicorn", "web.app:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2", "--no-access-log", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]
