FROM node:20-slim AS frontend-build

WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci --ignore-scripts 2>/dev/null || npm install
COPY frontend/ ./
RUN npm run build


# =============================================================================
# Stage 2: python-builder — compile Python wheels so the runtime stage needs
# no compiler toolchain and carries no build-time residue.
# =============================================================================
FROM python:3.11-slim AS python-builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt


# =============================================================================
# Stage 3: production — minimal runtime image.
# =============================================================================
FROM python:3.11-slim AS production

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       gnupg \
       nmap \
       iputils-ping \
       traceroute \
       tcpdump \
       curl \
       whois \
       dnsutils \
       libcap2-bin \
       snmp \
       net-tools \
       conntrack \
    && . /etc/os-release \
    && zeek_repo_version="${VERSION_ID%%.*}" \
    && echo "deb [signed-by=/usr/share/keyrings/zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/Debian_${zeek_repo_version}/ /" > /etc/apt/sources.list.d/security_zeek.list \
    && curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/Debian_${zeek_repo_version}/Release.key" | gpg --dearmor -o /usr/share/keyrings/zeek.gpg \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       zeek \
    && rm -rf /var/lib/apt/lists/* \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap \
    && setcap cap_net_raw+eip /bin/ping

COPY --from=python-builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels /wheels/* \
    && rm -rf /wheels

RUN groupadd -r netpulse && useradd -r -g netpulse -d /app -s /sbin/nologin netpulse

COPY app/ /app/app/
COPY scripts/ /app/scripts/
COPY --from=frontend-build /frontend/dist /app/static

RUN mkdir -p /app/data/scans /app/logs \
    && chown -R netpulse:netpulse /app

USER netpulse

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/health/ready || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
