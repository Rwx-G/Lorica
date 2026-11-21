#!/bin/sh
# SSH backend entrypoint (Story 12.11 IV1, Story 12.12 Lot K).
#
# Generates the host keys and one client key pair at start, authorizes
# the client key for the `tester` account, and publishes the private
# half on the shared volume for the hot-upgrade smoke, which logs in
# through a Lorica TCP stream. The client key is written under a temp
# name and renamed, so a reader never sees a partial file.
set -eu

ssh-keygen -A >/dev/null

if ! id tester >/dev/null 2>&1; then
    useradd -m -s /bin/sh tester
    # `*` rather than the locked `!`: a key login only, and an account
    # that no check reads as locked.
    usermod -p '*' tester
fi

mkdir -p /shared /home/tester/.ssh
rm -f /tmp/client_key /tmp/client_key.pub
ssh-keygen -q -t ed25519 -N '' -C hot-upgrade-smoke -f /tmp/client_key
cp /tmp/client_key.pub /home/tester/.ssh/authorized_keys
chown -R tester:tester /home/tester/.ssh
chmod 0700 /home/tester/.ssh
chmod 0600 /home/tester/.ssh/authorized_keys

(umask 077; cp /tmp/client_key /shared/.ssh-client-key.tmp)
mv /shared/.ssh-client-key.tmp /shared/ssh-client-key
rm -f /tmp/client_key

mkdir -p /run/sshd
exec /usr/sbin/sshd -D -e
