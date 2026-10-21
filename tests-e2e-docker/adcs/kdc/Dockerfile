# The MIT KDC of the AD CS harness (Story 13.1 Lot 4): one realm,
# CORP.EXAMPLE.ORG, created from scratch at every start so a run never
# inherits another run's principals or log.
FROM debian:trixie-slim
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        krb5-kdc krb5-admin-server \
    && rm -rf /var/lib/apt/lists/*
COPY krb5.conf /etc/krb5.conf
COPY kdc.conf /etc/krb5kdc/kdc.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
EXPOSE 88/tcp 88/udp
ENTRYPOINT ["/entrypoint.sh"]
