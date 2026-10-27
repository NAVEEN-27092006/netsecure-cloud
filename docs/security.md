# Security notes

## Included controls

- Passwords are stored with bcrypt; plain-text passwords are never saved.
- Session cookies are opaque, HTTP-only, `SameSite=Lax`, and stored only as SHA-256 hashes in the database.
- A production startup fails without `NETSECURE_SESSION_SECRET`.
- Input validation accepts only plain hostnames/IP addresses and a TCP port. URLs, paths, and shell input are not accepted.
- DNS results are examined before a connection. Restricted/private addresses are rejected unless `NETSECURE_ALLOW_PRIVATE_TARGETS=true` is deliberately enabled for a trusted local lab.
- TCP checks have a bounded four-second timeout and a per-user check rate limit.
- Login and first-account creation have per-IP rate limits.
- Security response headers, a restrictive same-origin content security policy, and audit logs are included.
- `.env` and `data/` are excluded from Git.

## Before public deployment

1. Use HTTPS and set `NETSECURE_COOKIE_SECURE=true`.
2. Generate a high-entropy `NETSECURE_SESSION_SECRET`; never commit it.
3. Keep `NETSECURE_ALLOW_PRIVATE_TARGETS=false` unless the app runs in a trusted private lab.
4. Restrict firewall ingress to the reverse proxy and application port as appropriate.
5. Back up the SQLite file securely, or migrate to PostgreSQL for concurrent/multi-user use.
6. Put the app behind a reverse proxy that handles TLS and sanitizes forwarded headers.
7. Monitor application logs and regularly update Python dependencies.

## Known boundaries

This app verifies that a TCP connection can be completed. It does **not** prove that an application is healthy, inspect traffic, discover vulnerabilities, scan networks, or detect all attacks. Only add targets that you are authorized to monitor.
