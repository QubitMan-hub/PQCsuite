# Build from the repository root: docker build -f products/readiness/deploy/Dockerfile -t acxelin-readiness .
FROM python:3.13-slim-trixie
RUN useradd --system --uid 10001 --home /scan scanner
COPY core /src/core
COPY products/readiness /src/readiness
RUN pip install --no-cache-dir /src/core "/src/readiness[crawler]" && rm -rf /src && pip uninstall -y pip
USER scanner
WORKDIR /scan
ENTRYPOINT ["acxelin-readiness"]
CMD ["scan", "."]
