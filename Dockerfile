FROM python:3.12-slim

WORKDIR /home/purple

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
RUN pip install --no-cache-dir \
    "a2a-sdk[http-server]>=0.3.20,<1.0" \
    "openai>=1.50.0" \
    "httpx>=0.28.1" \
    "pydantic>=2.10.0" \
    "uvicorn>=0.30.0" \
    "huggingface-hub>=0.24.0"

COPY src/ ./src/

ENV PYTHONUNBUFFERED=1
ENV OPENAI_MODEL=gpt-5.4

EXPOSE 8080

ENTRYPOINT ["python", "-m", "src.server"]
CMD ["--host", "0.0.0.0", "--port", "8080"]
