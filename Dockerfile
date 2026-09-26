# Debian 13 ships OpenSSL 3.5, so the system libssl negotiates ML-KEM and ML-DSA.
ARG BASE=python:3.13-slim-trixie
FROM ${BASE}
RUN useradd --system --uid 10001 --home /srv pqc
WORKDIR /app
COPY pyproject.toml README.md ./
COPY pqcsuite ./pqcsuite
RUN pip install --no-cache-dir . && pqcsuite doctor
USER pqc
WORKDIR /srv
EXPOSE 8443 9100
ENTRYPOINT ["pqcsuite"]
CMD ["tls", "edge", "--config", "/etc/pqcsuite/edge.toml"]
