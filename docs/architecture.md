# Architecture

```text
Browser dashboard
    |  same-origin HTTPS requests
    v
FastAPI application
    |-- authentication and rate limiting
    |-- target validation and safe TCP monitor
    `-- SQLite data store
            |-- users and sessions
            |-- approved targets
            |-- check history
            `-- audit log
```

## Request flow

1. An authenticated user creates a target using a hostname/IP and TCP port.
2. The API rejects URLs, paths, malformed hostnames, invalid ports, and duplicate targets.
3. The monitor resolves the hostname before connecting. Public deployments reject loopback, private, link-local, multicast, reserved, and unspecified addresses.
4. The monitor opens a TCP connection with a four-second timeout. It never runs shell commands or accepts a URL path.
5. The result, timing, and a safe error message are stored in SQLite.
6. The dashboard reads the newest result and the target's historical results through authenticated API endpoints.

## Data model

| Table | Purpose |
| --- | --- |
| `users` | Administrator username and bcrypt password hash. |
| `sessions` | SHA-256 hashes of opaque, HTTP-only session tokens. |
| `targets` | Explicitly approved TCP host/port targets. |
| `check_results` | Immutable result history for each target. |
| `audit_logs` | Authentication and target-management actions. |

## Deliberate design choices

- **FastAPI + vanilla JavaScript:** one deployable service and no frontend build process.
- **SQLite:** appropriate for a single-user portfolio project. Move to PostgreSQL for concurrent production use.
- **TCP check only:** availability is measurable and easy to explain. This is not a vulnerability scanner or intrusion-detection system.
- **Manual checks first:** avoids uncontrolled background traffic. A production scheduler should use a separate worker/queue with per-target intervals and alert integrations.
