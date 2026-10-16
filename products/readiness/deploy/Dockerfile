FROM python:3.14-slim
COPY pyproject.toml README.md /src/
COPY acxelin_readiness /src/acxelin_readiness
RUN pip install --no-cache-dir /src && rm -rf /src
WORKDIR /scan
ENTRYPOINT ["acxelin-readiness"]
CMD ["scan", "."]
