FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DNSSTACK_CONFIG=/app/config/config.yaml

# openssh-client is used by `dnsstack update` to run `pihole -up` over ssh.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY dnsstack ./dnsstack
RUN pip install .

RUN groupadd --system --gid 10001 dnsstack \
    && useradd --system --uid 10001 --gid dnsstack --create-home --home-dir /home/dnsstack dnsstack \
    && mkdir -p /data /app/config /app/lists \
    && chown -R dnsstack:dnsstack /data

USER dnsstack
VOLUME ["/data"]
EXPOSE 8080

ENTRYPOINT ["dnsstack"]
CMD ["status"]
