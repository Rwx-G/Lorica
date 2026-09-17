FROM python:3.12-slim
# openssl does the RSA work: key generation, the JWK modulus, and the
# RS256 signatures, so the fixture needs nothing beyond the standard
# library. Same base and shape as ../backend.
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /bin/false appuser
WORKDIR /app
COPY server.py .
USER appuser
CMD ["python3", "server.py"]
