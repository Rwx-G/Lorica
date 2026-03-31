Name:           lorica
Version:        0.3.0
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
mkdir -p %{buildroot}/var/lib/lorica

install -m 755 %{_sourcedir}/lorica %{buildroot}/usr/bin/lorica
install -m 644 %{_sourcedir}/dist/lorica.service %{buildroot}/usr/lib/systemd/system/lorica.service

%pre
getent group lorica >/dev/null || groupadd -r lorica
getent passwd lorica >/dev/null || useradd -r -g lorica -d /var/lib/lorica -s /sbin/nologin lorica

%post
chown -R lorica:lorica /var/lib/lorica
chmod 750 /var/lib/lorica
systemctl daemon-reload
systemctl enable lorica.service
echo ""
echo "  ================================================"
echo "  Lorica installed successfully!"
echo "  "
echo "  Start:     systemctl start lorica"
echo "  Dashboard: https://localhost:9443"
echo "  "
echo "  The admin password will be in the journal:"
echo "    journalctl -u lorica -n 20"
echo "  ================================================"
echo ""

%preun
systemctl stop lorica.service 2>/dev/null || true
systemctl disable lorica.service 2>/dev/null || true

%postun
systemctl daemon-reload

%files
%attr(755, root, root) /usr/bin/lorica
%attr(644, root, root) /usr/lib/systemd/system/lorica.service
%dir %attr(750, lorica, lorica) /var/lib/lorica
