# office-smtprelay

A small, low-maintenance SMTP relay for your local network that forwards mail to **Microsoft 365 / Exchange Online** through the **Microsoft Graph API** (OAuth 2.0, app-only), with a web UI to manage devices and the Microsoft connection.

It exists for devices that can only speak plain SMTP (printers, scanners, NAS boxes, legacy apps) in tenants where **Security Defaults** or Microsoft's retirement of Basic authentication for SMTP AUTH makes `smtp.office365.com` with a username and password unusable.

> **Status: work in progress.** The relay, the web UI and the container image work and are covered by tests. It has not yet been verified against a real Microsoft 365 tenant, and no release has been published yet.

## How it works

```
Device (fixed IP) --SMTP + STARTTLS + AUTH--> office-smtprelay --HTTPS / Graph sendMail--> Microsoft 365 --> recipient
                                                   |
                                                   +-- web UI (admin login): clients, Microsoft connection, logs
```

- Every device ("client") is identified by its **fixed IP address and** a **username/password**. Both are required; credentials are only accepted after STARTTLS.
- The relay authenticates to Microsoft with an **Entra ID app registration** (client credentials). No user password is ever stored on a device.
- Which mailboxes the relay may send as is controlled **on the Microsoft side** (optionally scoped with Exchange Online RBAC for Applications).
- Works with Security Defaults enabled. No extra licence and no Azure subscription are needed; an app registration is free.
- Single static Go binary, ~27 MB distroless image, runs as a non-root user with a read-only filesystem.

## Features

- SMTP server with STARTTLS, AUTH PLAIN and LOGIN (what printers use), per-device IP + login, brake on repeated failed logins.
- Web UI in **English and Dutch** (default set with `SMTPRELAY_LANG`, switchable per browser): dashboard, clients, unknown devices, logs with plain-language advice per problem, Microsoft 365 connection with a *Check connection* button, test mail, step-by-step help.
- Diagnostics for devices that cannot connect: wrong IP, wrong password, unknown user, TLS or sender problems, Microsoft refusals. Identical failures are merged so a misconfigured device cannot flood the log. Message contents are never logged.
- Secrets are encrypted at rest; passwords are stored as argon2id hashes; the client secret expiry is tracked and warned about.
- CLI for headless management (`office-smtprelay client ...`, `office-smtprelay graph ...`).

## Setup

1. **[Create the Entra ID app registration](docs/entra-setup.md)** (manual steps, with an optional helper script). You need the tenant ID, client ID and a client secret.
2. **Run the container** (see below).
3. Open the web UI, choose the admin password, enter the Microsoft connection, press *Check connection*, then add your devices as clients and copy the shown settings into each device.

### Run with Docker Compose

Use [`compose.yaml`](compose.yaml) as a starting point (also works with QNAP Container Station):

```bash
docker compose up -d
docker logs office-smtprelay      # the first start prints a one-time setup token
```

Open `http://<host>:8080`, enter the setup token and choose an admin password (or set `SMTPRELAY_ADMIN_PASSWORD` for the first start).

Devices connect to `<host>:587` (mapped to container port 2525) with **STARTTLS** and **authentication**. Give each device a fixed IP address.

### Configuration

All settings are environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `SMTPRELAY_DATA_DIR` | `/data` | Database, encryption key and generated certificate (mount a volume). |
| `SMTPRELAY_SMTP_ADDR` | `:2525` | SMTP listen address inside the container. |
| `SMTPRELAY_HTTP_ADDR` | `:8080` | Web UI listen address (plain HTTP). |
| `SMTPRELAY_LANG` | `en` | Default UI language: `en` or `nl`. |
| `SMTPRELAY_HOSTNAME` | OS hostname | Name in the SMTP greeting and the generated certificate. |
| `SMTPRELAY_PUBLIC_SMTP_PORT` | `587` | Port shown to admins for devices. |
| `SMTPRELAY_TLS_CERT` / `SMTPRELAY_TLS_KEY` | (generated) | Your own certificate and key (PEM). |
| `SMTPRELAY_TLS_NAMES` | | Extra names/IPs for the generated self-signed certificate. |
| `SMTPRELAY_TLS_MIN` | `1.2` | `1.1` or `1.0` only for very old devices. |
| `SMTPRELAY_MAX_MESSAGE_MB` | `35` | Maximum message size (1-150). |
| `SMTPRELAY_EVENT_RETENTION_DAYS` | `30` | How long log events are kept. |
| `SMTPRELAY_ADMIN_PASSWORD` | | Sets the UI password on first start (min. 12 characters); remove afterwards. |
| `SMTPRELAY_TRUST_PROXY` | `false` | Trust `X-Forwarded-For`/`-Proto` from a reverse proxy in front of the UI. |
| `TZ` | `UTC` | Time zone used to display times, e.g. `Europe/Brussels`. |

The data directory contains `secret.key`, which decrypts the stored Microsoft client secret. Back it up with the database; if it is lost, enter the client secret again.

## Security notes

- Never commit secrets, tenant IDs or real domain names.
- The web UI speaks plain HTTP by design; put it behind a reverse proxy that terminates HTTPS and set `SMTPRELAY_TRUST_PROXY=true`.
- Restrict network access to the SMTP port to your known client IPs (firewall rule). The relay also checks the source IP itself.
- `Mail.Send` as an application permission can send as any mailbox unless you scope it; see [docs/entra-setup.md](docs/entra-setup.md#3-recommended-limit-which-mailboxes-the-app-can-send-as).
- Under Docker Desktop (Windows/macOS) containers see a gateway address instead of the real client IP, so per-IP rules cannot be tested end-to-end there. On Linux hosts, publish the port normally and verify with a device on the LAN.

## Development

```bash
go test ./...                                   # unit and end-to-end tests (Microsoft is mocked)
docker build --build-arg VERSION=dev -t office-smtprelay:dev .
```

Requires Go (see `go.mod`). No cgo is needed; SQLite is the pure-Go `modernc.org/sqlite`.

## License

[MIT](LICENSE)
