# BH Socket Relay Admin

Single-binary admin panel for BH Socket relay nodes.

The admin panel is intentionally separate from `gsrnd`. If the panel is stopped
or crashes, the relay keeps running.

## Security model

- The panel never stores plaintext secrets.
- Generated secrets are returned once, then only a SHA-256 fingerprint is kept.
- The panel should bind to `127.0.0.1` and be exposed through VPN or an HTTPS
  reverse proxy with IP allowlisting.
- `BH_ADMIN_USER` and `BH_ADMIN_PASSWORD` are required.
- Audit events are appended to `audit.jsonl`.

## Build

```sh
cd admin
go build -trimpath -ldflags="-s -w" -o bhrelay-admin ./bhrelay-admin.go
```

## Install

```sh
install -m 0755 admin/bhrelay-admin /usr/local/bin/bhrelay-admin
install -m 0644 deploy/admin/bhrelay-admin.service /etc/systemd/system/bhrelay-admin.service
install -m 0600 deploy/admin/bhsocket-admin.env.example /etc/bhsocket-admin.env
mkdir -p /var/lib/bhsocket-admin
chown -R gsnet:gsnet /var/lib/bhsocket-admin
systemctl daemon-reload
systemctl enable --now bhrelay-admin
```

Then open the panel through your private access path, for example:

```sh
ssh -L 8730:127.0.0.1:8730 root@bh1.bhsocket.io
```

and browse to `http://127.0.0.1:8730`.

## Environment

- `BH_ADMIN_LISTEN`: HTTP bind address, default `127.0.0.1:8730`
- `BH_ADMIN_CLI`: path to `gsrn_cli`, default `/usr/bin/gsrn_cli`
- `BH_ADMIN_CLI_HOST`: reserved for future use; the current bundled `gsrn_cli`
  release only supports localhost reliably
- `BH_ADMIN_CLI_PORT`: relay CLI port, default `48001`
- `BH_ADMIN_DATA_DIR`: state directory, default `/var/lib/bhsocket-admin`
- `BH_ADMIN_USER`: required username
- `BH_ADMIN_PASSWORD`: required password
