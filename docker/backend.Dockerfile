FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System dependencies (for ping, nmap, packet capture, etc.)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       curl \
       gnupg \
       iputils-ping \
       nmap \
       tcpdump \
    && . /etc/os-release \
    && zeek_repo_version="${VERSION_ID%%.*}" \
    && echo "deb [signed-by=/usr/share/keyrings/zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/Debian_${zeek_repo_version}/ /" > /etc/apt/sources.list.d/security_zeek.list \
    && curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/Debian_${zeek_repo_version}/Release.key" | gpg --dearmor -o /usr/share/keyrings/zeek.gpg \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       zeek \
    && rm -rf /var/lib/apt/lists/*

COPY app /app
COPY scripts /scripts

# Install backend dependencies
# In a production deployment you should pin versions in requirements.txt.
RUN pip install --no-cache-dir \
      fastapi \
      "uvicorn[standard]" \
      sqlalchemy[asyncio] \
      asyncpg \
      pydantic \
      pydantic-settings \
      celery \
      redis \
      scapy \
      python-nmap \
      reportlab \
      slowapi \
      httpx \
      "python-jose[cryptography]" \
      "passlib[bcrypt]"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]