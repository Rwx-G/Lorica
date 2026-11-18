# The released Lorica the NFR1 measurement and the rollback scenarios
# compare against (Story 12.12 D-g): the signed .deb of the GitHub
# release, verified with gpgv against the repository's published key
# exactly as the CI job `test-deb-upgrade` does, then unpacked onto the
# same Debian 12 base as the e2e runtime image. Test image only.
#
# The key comes from a named build context, because the repository's
# .dockerignore keeps docs/ out of the default one:
#
#   docker build --build-context signing-key=docs \
#       -f tests-e2e-docker/baseline/Dockerfile tests-e2e-docker/baseline
#
# In compose: `additional_contexts: { signing-key: ../docs }`.

FROM debian:bookworm-20261104-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS fetch
ARG LORICA_BASELINE_VERSION=1.10.7
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg gpgv \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /fetch
COPY --from=signing-key lorica-signing-key.asc ./
RUN set -eu; \
    deb="lorica_${LORICA_BASELINE_VERSION}_amd64.deb"; \
    for asset in "$deb" "$deb.asc"; do \
        curl -fsSL --retry 3 -o "$asset" \
            "https://github.com/Rwx-G/Lorica/releases/download/v${LORICA_BASELINE_VERSION}/$asset"; \
    done; \
    gpg --dearmor < lorica-signing-key.asc > lorica-signing-key.gpg; \
    gpgv --keyring "$PWD/lorica-signing-key.gpg" "$deb.asc" "$deb"; \
    dpkg-deb -x "$deb" /pkg; \
    test -x /pkg/usr/bin/lorica

FROM debian:bookworm-20261104-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
# The same runtime packages as the e2e image, so the e2e entrypoints
# (socat forwarder, curl readiness probe, sqlite3 inspection) work here.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl libgssapi-krb5-2 socat sqlite3 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /bin/false lorica \
    && mkdir -p /var/lib/lorica /shared \
    && chown lorica:lorica /var/lib/lorica /shared
COPY --from=fetch /pkg/usr/bin/lorica /usr/local/bin/lorica
WORKDIR /var/lib/lorica
USER lorica
ENTRYPOINT ["lorica"]
CMD ["--version"]
