FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System dependencies (for ping, nmap, etc. as needed later)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY app /app
COPY scripts /scripts

# Install backend dependencies
# In a real deployment you would maintain a dedicated requirements file.
RUN pip install --no-cache-dir \
      fastapi \
      "uvicorn[standard]" \
      sqlalchemy[asyncio] \
      asyncpg \
      pydantic \
      celery \
      redis \
      scapy \
      python-nmap

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]