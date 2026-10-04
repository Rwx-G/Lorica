Name:           lorica
Version:        1.8.0
Release:        1%{?dist}
Summary:        Modern reverse proxy with built-in dashboard
License:        Apache-2.0
URL:            https://github.com/Rwx-G/Lorica
BuildArch:      x86_64

Requires:       ca-certificates

%description
A dashboard-first reverse proxy built in Rust. Single binary,
embedded web UI, no config files. HTTP/HTTPS proxying, WAF,
health checks, certificate management, Prometheus metrics.
Also ships lorica-mcp, the MCP server an operator's MCP client
launches; no service starts it.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/lib/systemd/system
mkdir -p %{buildroot}/usr/share/doc/lorica
mkdir -p %{buildroot}/usr/share/licenses/lorica
mkdir -p %{buildroot}/var/lib/lorica
mkdir -p %{buildroot}/var/lib/lorica/exported-certs
# The hot-upgrade staging zone /var/lib/lorica/upgrade (Story 8.4) is
# created 0700 at runtime by the upgrade endpoint - not pre-created here.
# No signing key is bundled: the Ed25519 public key is operator-managed
# (`upgrade_signing_pubkey_path`, e.g. /etc/lorica/upgrade-signing.pub).
# See docs/hot-upgrade.md.

install -m 755 %{_sourcedir}/lorica %{buildroot}/usr/bin/lorica
# The MCP server (Story 11.4). Installed, never started by the package:
# the operator's MCP client launches it. See the note in lorica.service.
install -m 755 %{_sourcedir}/lorica-mcp %{buildroot}/usr/bin/lorica-mcp
install -m 644 %{_sourcedir}/dist/lorica.service %{buildroot}/usr/lib/systemd/system/lorica.service

# LICENSE and NOTICE (Apache-2.0 section 4(d) compliance)
install -m 644 %{_sourcedir}/LICENSE %{buildroot}/usr/share/licenses/lorica/LICENSE
install -m 644 %{_sourcedir}/NOTICE %{buildroot}/usr/share/licenses/lorica/NOTICE

# The service state an upgrade carries across, read here, before the old
# package's preun can change it, and restored by posttrans: `install` on
# a first install ($1 = 1), otherwise whether the unit was enabled and
# whether it was running. /run belongs to root, so the service account
# cannot plant a record, and it is cleared at boot.
%pre
getent group lorica >/dev/null || groupadd -r lorica
getent passwd lorica >/dev/null || useradd -r -g lorica -d /var/lib/lorica -s /sbin/nologin lorica
if [ "$1" -eq 1 ]; then
    printf 'install\n' > /run/lorica-package.state 2>/dev/null || :
else
    enabled=no
    active=no
    if systemctl is-enabled --quiet lorica.service 2>/dev/null; then enabled=yes; fi
    if [ "$(systemctl is-active lorica.service 2>/dev/null)" = active ]; then active=yes; fi
    printf 'enabled=%s active=%s\n' "$enabled" "$active" > /run/lorica-package.state 2>/dev/null || :
fi
:

# Not recursive: everything below the data directory is the service
# account's, and root walking a tree that account controls follows
# whatever it planted there (a hard link to a root-owned file would
# change hands). The node creates what it writes with its own owner,
# and a recursive pass also reset, on every upgrade, the owner an
# operator gave exported certificates.
%post
chown lorica:lorica /var/lib/lorica
chmod 750 /var/lib/lorica
# Default cert-export zone (v1.4.1). Empty until the operator
# turns the feature on via the dashboard.
if [ ! -d /var/lib/lorica/exported-certs ]; then
    mkdir -p /var/lib/lorica/exported-certs
fi
chown lorica:lorica /var/lib/lorica/exported-certs
chmod 750 /var/lib/lorica/exported-certs
echo ""
echo "  ================================================"
echo "  Lorica installed successfully!"
echo "  "
echo "  Dashboard: https://127.0.0.1:9443"
echo "    (TLS with a self-signed certificate; listens on"
echo "     localhost only, not reachable from other machines."
echo "     Before you log in, check that the fingerprint your"
echo "     browser shows is the one the node serves:"
echo "       sudo openssl x509 -noout -fingerprint -sha256 \\"
echo "         -in /var/lib/lorica/management/served-cert.pem"
echo "     Another local process can hold the port while"
echo "     lorica is stopped, and it would receive the password.)"
echo "  "
echo "  The initial admin password is written to a 0600 file:"
echo "    sudo cat /var/lib/lorica/initial-admin-password"
echo "    (delete it after your first login)"
echo "  "
echo "  Customize with: systemctl edit lorica"
echo "    Add an [Service] override with ExecStart= to"
echo "    replace the default command line. Example:"
echo "  "
echo "    [Service]"
echo "    ExecStart="
echo "    ExecStart=/usr/bin/lorica --data-dir /var/lib/lorica \\"
echo "      --workers 6 \\"
echo "      --management-port 9443 \\"
echo "      --http-port 8080 \\"
echo "      --https-port 8443 \\"
echo "      --log-level info"
echo "  "
echo "  Available flags:"
echo "    --workers N          worker processes (0 = single-process)"
echo "    --management-port N  dashboard port (default: 9443)"
echo "    --http-port N        HTTP proxy port (default: 8080)"
echo "    --https-port N       HTTPS proxy port (default: 8443)"
echo "    --cluster-listen H:P cluster plane listener (opt-in,"
echo "                         disabled by default; 9444 by convention,"
echo "                         see docs/cluster.md before opening it)"
echo "    --log-level LEVEL    trace|debug|info|warn|error"
echo "  ================================================"
echo ""

# On an upgrade, rpm runs the new package's pre and post scriptlets, then
# the OLD package's preun and postun, then the new package's posttrans.
# So the service is started in posttrans, the one scriptlet that runs
# after the old package is gone, and preun stops and disables it only
# when the package is erased ($1 is the number of versions left
# installed: 0 on erase, 1 on upgrade). The preun of 1.8.0 and earlier
# still stops and disables it on the way to this version; posttrans puts
# back what pre recorded before that ran.
%preun
if [ "$1" -eq 0 ]; then
    systemctl stop lorica.service 2>/dev/null || true
    systemctl disable lorica.service 2>/dev/null || true
fi

%postun
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi

# A first install enables and starts the service. An upgrade restores what
# pre recorded: enabled again only if it was enabled, restarted only if it
# was running, so a service the operator stopped or disabled stays that
# way. Without a record nothing is enabled or started.
#
# /run/systemd/system exists only while systemd runs. Without it (an image
# build, a container) the unit is enabled for the first boot and nothing
# is started. A failed start is reported without failing the transaction,
# which could not be rolled back from here anyway.
%posttrans
previous_state=$(cat /run/lorica-package.state 2>/dev/null || :)
rm -f /run/lorica-package.state
enable=no
start=no
case "$previous_state" in
    install) enable=yes; start=yes ;;
    *enabled=yes*) enable=yes ;;
esac
case "$previous_state" in
    *active=yes*) start=yes ;;
esac
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
if [ "$enable" = yes ] && command -v systemctl >/dev/null 2>&1; then
    systemctl enable lorica.service
fi
if [ "$start" = yes ] && [ -d /run/systemd/system ]; then
    systemctl restart lorica.service \
        || echo "lorica: the service did not start; see journalctl -u lorica.service" >&2
elif [ "$start" = no ]; then
    echo "lorica: lorica.service was left stopped, as it was before this transaction;" \
        "start it with: systemctl start lorica.service"
fi
:

%files
%license /usr/share/licenses/lorica/LICENSE
%license /usr/share/licenses/lorica/NOTICE
%attr(755, root, root) /usr/bin/lorica
%attr(755, root, root) /usr/bin/lorica-mcp
%attr(644, root, root) /usr/lib/systemd/system/lorica.service
%dir %attr(750, lorica, lorica) /var/lib/lorica
%dir %attr(750, lorica, lorica) /var/lib/lorica/exported-certs
