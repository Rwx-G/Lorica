# The CES fixture of the AD CS harness (Story 13.1 Lot 4), its probe
# client, and the KDC that never answers. Debian packages only: the
# fixture needs python-gssapi's raw context flags and channel bindings
# against the system MIT library, not a pip build of them.
FROM debian:trixie-slim
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 python3-cryptography python3-gssapi \
    && rm -rf /var/lib/apt/lists/*
COPY krb5.conf /etc/krb5.conf
WORKDIR /app
COPY server.py probe.py blackhole.py harness_ca.py ./
CMD ["python3", "/app/server.py"]
