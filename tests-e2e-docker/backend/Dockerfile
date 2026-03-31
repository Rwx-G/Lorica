FROM python:3.12-slim
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY server.py .
CMD ["python3", "server.py"]
