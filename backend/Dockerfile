# Multi-stage build for minimal attack surface
FROM python:3.11-slim as builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final Runtime Container
FROM python:3.11-slim as runner

WORKDIR /app

# Run as non-privileged security user
RUN groupadd -g 10001 shieldgroup && \
    useradd -u 10001 -g shieldgroup -s /bin/bash -m shielduser

COPY --from=builder /root/.local /home/shielduser/.local
COPY . /app

RUN chown -R shielduser:shieldgroup /app
USER shielduser
ENV PATH=/home/shielduser/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
