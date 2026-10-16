# Build from the repository root: docker build -f products/readiness/deploy/Dockerfile -t acxelin-readiness .
FROM python:3.13-slim-trixie
RUN useradd --system --uid 10001 --home /scan scanner
COPY core /src/core
COPY products/readiness /src/readiness
RUN pip install --no-cache-dir /src/core "/src/readiness[crawler]" && rm -rf /src && pip uninstall -y pip
# The console keeps its settings, certificates and token here; mount a volume to keep them.
RUN mkdir -p /data && chown scanner /data
ENV ACXELIN_READINESS_HOME=/data/console
VOLUME /data
USER scanner
WORKDIR /scan
ENTRYPOINT ["acxelin-readiness"]
CMD ["scan", "."]
