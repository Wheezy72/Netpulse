# =============================================================================
# Stage 1: builder – compile Python wheels and install build-time tools.
# =============================================================================
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Build-time OS deps (compilers etc.) – not copied to the runtime stage.
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
# Stage 2: runtime – minimal Debian base, no compilers, no source code.
# =============================================================================
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Runtime OS deps only – keep this list small.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    iputils-ping \
    libpq5 \
    nmap \
    tcpdump \
    && . /etc/os-release \
    && zeek_repo_ver="${VERSION_ID%%.*}" \
    && echo "deb [signed-by=/usr/share/keyrings/zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/Debian_${zeek_repo_ver}/ /" > /etc/apt/sources.list.d/security_zeek.list \
    && curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/Debian_${zeek_repo_ver}/Release.key" | gpg --dearmor -o /usr/share/keyrings/zeek.gpg \
    && apt-get update && apt-get install -y --no-install-recommends zeek \
    && rm -rf /var/lib/apt/lists/*

# Install pre-built wheels from stage 1 – no compiler needed here.
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels /wheels/* \
    && rm -rf /wheels

COPY app /app/app
COPY scripts /app/scripts

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]