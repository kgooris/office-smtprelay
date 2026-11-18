# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub: **Security → Report a vulnerability** on this repository. Do not open a public issue. Include the version, how to reproduce it, and the impact you expect. You will get an answer as soon as possible.

## Automated checks

Dependabot proposes dependency updates weekly. `govulncheck`, CodeQL and Trivy run on every push, pull request and every Monday.

## Hardening tips

See the *Security notes* in the [README](README.md): put the web UI behind HTTPS, restrict the SMTP port to known device IPs, and scope the Microsoft app with RBAC so it can only send as the mailboxes you choose.
