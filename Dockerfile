# MirageSSH - Multi-Stage Container Build
FROM python:3.11-slim as builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final Runtime Image
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed wheels from builder stage
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH
ENV PYTHONPATH=/app/src

# Copy project files
COPY config/ ./config/
COPY src/ ./src/
COPY pyproject.toml .

# Create directory structure for persistent runtime artifacts
RUN mkdir -p data/logs data/recordings data/host_keys

# Expose SSH Honeypot port (2222) and Web SOC Dashboard port (8080)
EXPOSE 2222 8080

ENTRYPOINT ["python", "-m", "miragessh"]
CMD ["--config", "config/default_config.yaml"]
