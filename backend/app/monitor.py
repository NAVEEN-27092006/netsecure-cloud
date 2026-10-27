"""Safe, timeout-bound TCP availability checks for explicitly configured targets."""

from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class ProbeResult:
    status: str
    response_ms: float | None
    error_message: str | None


def _is_blocked_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    )


def _resolve_public_addresses(host: str, port: int, allow_private_targets: bool) -> list[tuple]:
    try:
        candidates = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise ValueError("DNS lookup failed for this target.") from error

    safe_candidates: list[tuple] = []
    for family, socktype, protocol, _, sockaddr in candidates:
        address = ipaddress.ip_address(sockaddr[0])
        if not allow_private_targets and _is_blocked_address(address):
            continue
        safe_candidates.append((family, socktype, protocol, sockaddr))

    if not safe_candidates:
        raise ValueError(
            "This target resolves to a private or restricted address. "
            "Enable local-lab targets only in a trusted environment."
        )
    return safe_candidates


def probe_tcp(host: str, port: int, *, timeout_seconds: float = 4.0, allow_private_targets: bool = False) -> ProbeResult:
    """Resolve then connect to a target. No shell commands, URLs, or arbitrary paths are used."""
    try:
        candidates = _resolve_public_addresses(host, port, allow_private_targets)
    except ValueError as error:
        return ProbeResult(status="offline", response_ms=None, error_message=str(error))

    last_error: OSError | None = None
    for family, socktype, protocol, sockaddr in candidates:
        started = time.perf_counter()
        try:
            with socket.socket(family, socktype, protocol) as connection:
                connection.settimeout(timeout_seconds)
                connection.connect(sockaddr)
            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
            return ProbeResult(status="online", response_ms=elapsed_ms, error_message=None)
        except (socket.timeout, OSError) as error:
            last_error = error

    if isinstance(last_error, socket.timeout):
        message = "Connection timed out."
    elif last_error is not None:
        message = "Connection was refused or could not be completed."
    else:
        message = "No usable network address was found."
    return ProbeResult(status="offline", response_ms=None, error_message=message)
