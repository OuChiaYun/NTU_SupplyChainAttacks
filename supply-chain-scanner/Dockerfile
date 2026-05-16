FROM node:22-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV CI=true
ENV NPM_CONFIG_FUND=false
ENV NPM_CONFIG_AUDIT=false

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    git \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install npq as the supply-chain risk scanning tool.
# This only installs the scanner itself inside Docker.
# The scanner uses `npq <package>@<version> --plain`, not `npq install ...`.
RUN npm install -g npq

WORKDIR /scanner

COPY requirements.txt /scanner/requirements.txt
RUN python3 -m venv /opt/scanner-venv \
    && /opt/scanner-venv/bin/pip install --no-cache-dir -r /scanner/requirements.txt

COPY scanner.py /scanner/scanner.py
COPY cve_enricher.py /scanner/cve_enricher.py

ENV PATH="/opt/scanner-venv/bin:${PATH}"

ENTRYPOINT ["python3", "/scanner/scanner.py"]
