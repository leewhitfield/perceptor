FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git python3 python3-venv python3-dev build-essential \
    pkg-config libleveldb-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /app
COPY pyproject.toml README.md ./
COPY forensic_orchestrator ./forensic_orchestrator

RUN uv sync --frozen

FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    sleuthkit ewf-tools qemu-utils ntfs-3g cryptsetup util-linux \
    libesedb-utils exiftool poppler-utils tesseract-ocr \
    libfsntfs-utils python3-libfsntfs libvshadow-utils dislocker libbde-utils \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 perceptor
RUN mkdir -p /var/lib/perceptor /evidence /opt/perceptor-tools && \
    chown -R perceptor:perceptor /var/lib/perceptor /evidence /opt/perceptor-tools

USER perceptor
WORKDIR /app

COPY --from=builder --chown=perceptor:perceptor /app /app

ENV PATH="/app/.venv/bin:${PATH}"
ENV PERCEPTOR_ROOT="/var/lib/perceptor"
ENV PERCEPTOR_TOOLS_ROOT="/opt/perceptor-tools"

ENTRYPOINT ["perceptor"]
CMD ["--help"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD ["perceptor", "standalone", "health", "--format", "json"]
