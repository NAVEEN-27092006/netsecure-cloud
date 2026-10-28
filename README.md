# NetSecure Cloud

NetSecure Cloud is a secure, small-scale web dashboard for checking the TCP availability of hosts and services that you are explicitly authorized to monitor. It stores response time and check history, and is designed as an end-to-end networking, Python, web, security, and deployment portfolio project.

> This is an availability monitor, not an intrusion-detection system, vulnerability scanner, or network discovery tool.

## What is included

- First-run administrator setup and secure sign-in/sign-out
- Bcrypt password hashes and HTTP-only opaque session cookies
- Validated, explicitly configured TCP monitoring targets
- Private/reserved-address protection by default to reduce SSRF-style risk
- Manual reachability checks with a four-second timeout
- Current status, response time, result history, and SQLite persistence
- Input validation, rate limits, security headers, audit logs, tests, Docker support, and CI

## Architecture

```text
Browser dashboard -> FastAPI API -> safe TCP monitor -> SQLite database
```

Read [the detailed architecture](docs/architecture.md) and [the security notes](docs/security.md) before deployment.

## Quick start on Windows PowerShell

Prerequisite: Python 3.11 or newer.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:PYTHONPATH = "$PWD\backend"
$env:NETSECURE_SESSION_SECRET = "replace-this-with-a-long-random-value"
uvicorn app.main:app --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). On the first visit, create the administrator account with a password of at least 12 characters.

For a trusted local-network lab only, add this before starting the server:

```powershell
$env:NETSECURE_ALLOW_PRIVATE_TARGETS = "true"
```

Do **not** enable that option on a public deployment.

## Run with Docker

Set a secure `NETSECURE_SESSION_SECRET` in your shell, then run:

```powershell
docker compose up --build
```

The included compose file stores SQLite data in a named Docker volume. For public use, place the container behind HTTPS and set `NETSECURE_COOKIE_SECURE=true`.

## API overview

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Public health status. |
| `GET` | `/api/setup-status` | Whether the first administrator must be created. |
| `POST` | `/api/auth/bootstrap` | Create the only initial administrator. |
| `POST` | `/api/auth/login` | Create an authenticated session. |
| `POST` | `/api/auth/logout` | End the current session. |
| `GET` | `/api/dashboard` | Read target status summary. |
| `POST` | `/api/targets` | Add an approved target. |
| `POST` | `/api/targets/{id}/check` | Run one TCP check. |
| `GET` | `/api/targets/{id}/history` | Read stored history. |
| `DELETE` | `/api/targets/{id}` | Remove a target and its history. |

Development-only interactive API documentation is available at `/docs`.

## Tests

```powershell
$env:PYTHONPATH = "$PWD\backend"
python -m unittest discover -s tests -v
```

The test suite covers protected endpoints, first-run setup, target creation, result persistence, history, deletion, and the private-target protection setting.

## Suggested next improvements

1. Replace SQLite with PostgreSQL before multi-user/high-volume use.
2. Add a separate scheduled worker for recurring checks rather than running jobs inside the web process.
3. Add e-mail, Slack, or webhook notifications for state changes.
4. Add role-based users and CSRF protection if the product becomes multi-user.
5. Add HTTPS/reverse-proxy deployment configuration for your selected cloud provider.

## Live Demo

[Open NetSecure Cloud](https://netsecure-cloud.onrender.com)
