# Debian 13 ships OpenSSL 3.5, so the system libssl negotiates ML-KEM and ML-DSA.
# Pinned by digest so a rebuild uses the same base; Dependabot proposes updates.
# Build from the repository root: docker build -f products/tls/deploy/Dockerfile -t acxelin-tls .
ARG BASE=python:3.13-slim-trixie@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b
FROM ${BASE}
# Apply distribution security updates even when the pinned base predates their publication.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --home /srv acxelin
COPY core /src/core
COPY products/tls /src/tls
# pip is not needed at run time and carries its own vendored packages, so it leaves the image.
RUN pip install --no-cache-dir /src/core /src/tls && rm -rf /src && pip uninstall -y pip && acxelin-tls doctor
USER acxelin
WORKDIR /srv
EXPOSE 8443 9100
ENTRYPOINT ["acxelin-tls"]
# With no arguments, the one-minute tour; deployments name their command (edge --config ..., as the Helm chart does).
CMD ["try"]
