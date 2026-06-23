# =============================================================================
# Stage 1: frontend-builder – compile Vue SPA static assets
# =============================================================================
FROM node:20-slim AS frontend-builder

WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci --ignore-scripts 2>/dev/null || npm install
COPY frontend/ ./
RUN npm run build

# =============================================================================
# Stage 2: python-builder – compile Python wheels for minimal runtime
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
    libpq-dev \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# =============================================================================
# Stage 3: runtime – minimal runtime image containing frontend & backend
# =============================================================================
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install critical system tools (including traceroute and network tools)
# Aggressively clean apt lists to keep container size small.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    iputils-ping \
    libpq5 \
    nmap \
    tcpdump \
    traceroute \
    net-tools \
    && . /etc/os-release \
    && zeek_repo_ver="${VERSION_ID%%.*}" \
    && echo "deb [signed-by=/usr/share/keyrings/zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/Debian_${zeek_repo_ver}/ /" > /etc/apt/sources.list.d/security_zeek.list \
    && curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/Debian_${zeek_repo_ver}/Release.key" | gpg --dearmor -o /usr/share/keyrings/zeek.gpg \
    && apt-get update && apt-get install -y --no-install-recommends zeek \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* /var/cache/debconf/*

# Install pre-built wheels from Stage 2
COPY --from=python-builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels /wheels/* \
    && rm -rf /wheels

# Copy application files
COPY app /app/app
COPY scripts /app/scripts

# Copy static frontend assets built in Stage 1
COPY --from=frontend-builder /frontend/dist /app/static

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/api/health/ready || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]