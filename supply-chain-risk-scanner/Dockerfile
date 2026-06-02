FROM node:22-bookworm

ENV CI=true
ENV NPM_CONFIG_FUND=false
ENV NPM_CONFIG_AUDIT=false

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g npq

WORKDIR /scanner

COPY requirements.txt .
RUN python3 -m venv /opt/scanner-venv \
    && /opt/scanner-venv/bin/pip install --no-cache-dir -r requirements.txt

COPY models.py scanner.py main.py .

ENV PATH="/opt/scanner-venv/bin:${PATH}"

ENTRYPOINT ["python3", "/scanner/main.py"]
