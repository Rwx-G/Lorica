Name:           lorica
Version:        1.6.0
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
install -m 644 %{_sourcedir}/dist/lorica.service %{buildroot}/usr/lib/systemd/system/lorica.service

# LICENSE and NOTICE (Apache-2.0 section 4(d) compliance)
install -m 644 %{_sourcedir}/LICENSE %{buildroot}/usr/share/licenses/lorica/LICENSE
install -m 644 %{_sourcedir}/NOTICE %{buildroot}/usr/share/licenses/lorica/NOTICE

%pre
getent group lorica >/dev/null || groupadd -r lorica
getent passwd lorica >/dev/null || useradd -r -g lorica -d /var/lib/lorica -s /sbin/nologin lorica

%post
chown -R lorica:lorica /var/lib/lorica
chmod 750 /var/lib/lorica
# Default cert-export zone (v1.4.1). Empty until the operator
# turns the feature on via the dashboard.
if [ ! -d /var/lib/lorica/exported-certs ]; then
    mkdir -p /var/lib/lorica/exported-certs
fi
chown lorica:lorica /var/lib/lorica/exported-certs
chmod 750 /var/lib/lorica/exported-certs
systemctl daemon-reload
systemctl enable lorica.service
systemctl restart lorica.service 2>/dev/null || systemctl start lorica.service
echo ""
echo "  ================================================"
echo "  Lorica installed successfully!"
echo "  "
echo "  Dashboard: http://127.0.0.1:9443"
echo "    (listens on localhost only - not reachable"
echo "     from other machines)"
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
echo "    --log-level LEVEL    trace|debug|info|warn|error"
echo "  ================================================"
echo ""

%preun
systemctl stop lorica.service 2>/dev/null || true
systemctl disable lorica.service 2>/dev/null || true

%postun
systemctl daemon-reload

%files
%license /usr/share/licenses/lorica/LICENSE
%license /usr/share/licenses/lorica/NOTICE
%attr(755, root, root) /usr/bin/lorica
%attr(644, root, root) /usr/lib/systemd/system/lorica.service
%dir %attr(750, lorica, lorica) /var/lib/lorica
%dir %attr(750, lorica, lorica) /var/lib/lorica/exported-certs
