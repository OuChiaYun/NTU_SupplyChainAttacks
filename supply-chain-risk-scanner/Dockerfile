FROM node:22-bookworm

ENV CI=true
ENV NPM_CONFIG_FUND=false
ENV NPM_CONFIG_AUDIT=false

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    bash \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g npq

# GuardDog + requests 裝進同一個 python(system),避免 venv 隔離問題
RUN pip install --break-system-packages --ignore-installed guarddog requests

WORKDIR /scanner

COPY models.py scanner.py main.py entrypoint.sh ./
RUN chmod +x /scanner/entrypoint.sh

ENTRYPOINT ["/scanner/entrypoint.sh"]
