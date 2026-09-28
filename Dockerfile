FROM python:3.14-slim
COPY pyproject.toml README.md /src/
COPY wolfpack /src/wolfpack
RUN pip install --no-cache-dir /src && rm -rf /src
WORKDIR /scan
ENTRYPOINT ["wolfpack"]
CMD ["scan", "."]
