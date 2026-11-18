<div align="center">

# 📬 office-smtprelay

**Let printers, scanners and legacy apps send mail through Microsoft 365, without Basic auth or SMTP AUTH on the Microsoft side.**

A small, self-hosted SMTP relay with a friendly web UI. Your devices send mail to it with a normal SMTP login (STARTTLS + username and password), and it forwards the mail to Microsoft 365 through the Microsoft Graph API with a secure app registration.

[![CI](https://github.com/kgooris/office-smtprelay/actions/workflows/ci.yml/badge.svg)](https://github.com/kgooris/office-smtprelay/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/kgooris/office-smtprelay?sort=semver)](https://github.com/kgooris/office-smtprelay/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Docker image](https://img.shields.io/badge/ghcr.io-multi--arch-2496ED?logo=docker&logoColor=white)

Web UI in English and Dutch

</div>

---

## Why would you need this?

Many devices can send mail, but only in a very basic way: a scan-to-email printer, a NAS that reports disk problems, an alarm system, an old line-of-business app. They all expect an SMTP server with a username and password, and they cannot do modern sign-in (OAuth, MFA).

Microsoft 365 has been closing exactly that door:

- **Security Defaults** (on by default for new tenants) block Basic authentication, so a device logging in to `smtp.office365.com` fails with `535 5.7.3 Authentication unsuccessful`.
- Microsoft is **phasing out Basic auth for SMTP AUTH** in Exchange Online step by step. Check your tenant's Message Center for the date that applies to you.
- The official alternatives all have a catch: SMTP relay through a connector needs a **fixed public IP**, a dedicated mailbox needs an **extra licence**, High Volume Email needs an **Azure subscription** and only reaches internal recipients, and third-party relay services mean sending your mail through another company.

office-smtprelay closes the gap with one small server on your own network:

- Your devices keep working exactly as they do now: plain SMTP login with STARTTLS, no firmware update needed.
- Towards Microsoft it uses a modern, supported route (Graph API with an app registration), so Security Defaults can stay on and no password of a real mailbox lives on a printer.
- It is free to run: no extra licence, no Azure subscription, no fixed public IP.
- You stay in control: per-device logins, limits and rules, a log that explains why a device failed, and an emergency stop. Microsoft-side scoping (RBAC) decides which mailboxes may be used as sender.

Typical users: small offices and schools with a few printers or scanners, home labs, and IT admins who inherited legacy equipment.

> **Status:** the relay and web UI have been tested against a real Microsoft 365 tenant, and automated tests cover the rest with Microsoft mocked. Releases are published from version tags; see [Releases](https://github.com/kgooris/office-smtprelay/releases) and [Setup](#setup).

## How it works

```
Device (fixed IP) --SMTP + STARTTLS + AUTH--> office-smtprelay --HTTPS / Graph sendMail--> Microsoft 365 --> recipient
                                                   |
                                                   +-- web UI (admin login): clients, Microsoft connection, logs
```

- Every device ("client") is identified by its **fixed IP address and** a **username/password**. Both are required; credentials are only accepted after STARTTLS.
- The relay authenticates to Microsoft with an **Entra ID app registration** (client credentials). No user password is ever stored on a device.
- Which mailboxes the relay may send as is controlled **on the Microsoft side** (optionally scoped with Exchange Online RBAC for Applications).
- Rules per device are optional and can be tried in a **test mode** that only logs what would be refused.
- Works with Security Defaults enabled. No extra licence and no Azure subscription are needed; an app registration is free.
- Single static Go binary, ~27 MB distroless image, runs as a non-root user with a read-only filesystem.

## Features

- SMTP server with STARTTLS, AUTH PLAIN and LOGIN (what printers use), per-device IP (or several ranges) + login, brake on repeated failed logins. Optional extra ports for SMTP over TLS and, for old devices only, without encryption.
- **Rules per device**, each *off*, *test (log only)* or *on*, with presets Basic / Recommended / Strict: allowed or forced sender, internal-only or listed recipients, limits per hour / day / recipients / size, Reply-To, subject prefix, Bcc, attachment type rules, minimum TLS.
- **Emergency stop** that pauses all sending (UI and `office-smtprelay pause|resume`).
- Web UI in **English and Dutch**, mobile friendly, no JavaScript: dashboard, devices, unknown devices, logs with plain-language advice per problem, Microsoft 365 connection with a *Check connection* button, test mail, notifications by mail, certificate and port management, backup and restore, step-by-step help.
- **Admin security:** several users (administrator / read-only), two-step verification (TOTP with recovery codes), session length, restricting the UI to your own network with lock-out protection.
- Diagnostics for devices that cannot connect: wrong IP, wrong password, unknown user, TLS or sender problems, Microsoft refusals. Identical failures are merged so a misconfigured device cannot flood the log. Message contents are never logged.
- Secrets are encrypted at rest; passwords are stored as argon2id hashes; the client secret expiry is tracked and warned about.
- CLI for headless management (`client`, `graph`, `user`, `backup`, `pause` / `resume`).

## Setup

1. **[Create the Entra ID app registration](docs/entra-setup.md)** (manual steps, with an optional helper script). You need the tenant ID, client ID and a client secret.
2. **Run the server** (see below).
3. Open the web UI, choose the admin password, enter the Microsoft connection, press *Check connection*, then add your devices as clients and copy the shown settings into each device.

### Get it

Pick one:

- **Docker image** (multi-arch amd64 / arm64): `docker pull ghcr.io/kgooris/office-smtprelay:latest`. Pin a version such as `:1.0.0` for production.
- **Static binary** for Linux amd64 / arm64 with checksums: download from [Releases](https://github.com/kgooris/office-smtprelay/releases).
- **From source:** see [Development](#development).

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
- Under Docker Desktop (Windows/macOS) the relay sees a gateway address instead of the real client IP, so per-IP rules cannot be tested end-to-end there. On Linux hosts, publish the port normally and verify with a device on the LAN.

## Development

```bash
go test ./...                                   # unit and end-to-end tests (Microsoft is mocked)
docker build --build-arg VERSION=dev -t office-smtprelay:dev .
```

Requires Go (see `go.mod`). No cgo is needed; SQLite is the pure-Go `modernc.org/sqlite`.

## Releasing

Maintainers: push a version tag and GitHub Actions runs the tests, builds the multi-arch image, pushes it to `ghcr.io` and creates a GitHub release with the Linux binaries and `SHA256SUMS`.

```bash
git tag v1.0.0
git push origin v1.0.0
```

After the first release, make the `ghcr.io` package public (GitHub → Packages → office-smtprelay → Package settings) so people can pull it without logging in.

## License

[MIT](LICENSE)
