FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System dependencies (for ping, nmap, packet capture, etc.)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       iputils-ping \
       nmap \
       tcpdump \
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
      celery \
      redis \
      scapy \
      python-nmap \
      fpdf2 \
      "python-jose[cryptography]" \
      "passlib[bcrypt]"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]