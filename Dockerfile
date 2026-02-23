FROM node:20-slim AS frontend-build

WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci --ignore-scripts 2>/dev/null || npm install
COPY frontend/ ./
RUN npm run build

FROM python:3.11-slim AS production

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
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
    && rm -rf /var/lib/apt/lists/* \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap \
    && setcap cap_net_raw+eip /bin/ping

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

RUN groupadd -r netpulse && useradd -r -g netpulse -d /app -s /sbin/nologin netpulse

COPY app/ /app/app/
COPY scripts/ /app/scripts/
COPY --from=frontend-build /frontend/dist /app/static

RUN mkdir -p /app/data/scans /app/logs \
    && chown -R netpulse:netpulse /app

USER netpulse

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
