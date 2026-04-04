FROM python:3.12-slim
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /bin/false appuser
WORKDIR /app
COPY server.py .
USER appuser
CMD ["python3", "server.py"]
