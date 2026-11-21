# The SSH backend of the hot-upgrade profile (Story 12.11 IV1, Story
# 12.12 Lot K): Debian's openssh-server, approved for the e2e images only
# (Story 12.11 Resolved 4, Story 12.12 D-p). Its keys are generated when
# the container starts, never at build time, so no key material is in
# the image or the repository.
FROM debian:bookworm-20261104-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
