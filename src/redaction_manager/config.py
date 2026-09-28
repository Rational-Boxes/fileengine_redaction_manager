# Copyright (C) 2026 James Hickman
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Environment-driven configuration. RM_* throughout — this service shares no
configuration namespace with the deployment, because it shares no deployment.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(key: str, default: str = "") -> str:
    v = os.environ.get(key)
    return v if v else default


def _int(key: str, default: int) -> int:
    try:
        return int(_env(key, str(default)))
    except ValueError:
        return default


@dataclass
class Config:
    # Two supported deployment shapes, and the choice must be explicit.
    #
    #   LOOPBACK (default) — the operator reaches it over an SSH tunnel. The
    #     application is not on the network at all, so there is no network
    #     control to get wrong.
    #
    #   ALLOWLISTED — bound to an interface, with the firewall admitting only
    #     known administrator addresses. Reachable, narrowly.
    #
    # Binding off-loopback with no allowlist is refused (see problems()). That
    # is the one combination that is never intended, and it is exactly what a
    # hurried "it wasn't reachable from my laptop" change produces.
    host: str = field(default_factory=lambda: _env("RM_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _int("RM_PORT", 8105))

    # Administrator addresses, as CIDRs. The FIREWALL is the enforcement; this
    # is the application's own second check, and it exists because a firewall
    # rule is a thing someone edits on a Friday.
    #
    # It compares the SOCKET PEER, never X-Forwarded-For. There is no proxy in
    # front of this by design, and trusting a header here would let a caller
    # choose the address that authorises it — the same trap the deployment's
    # own client-IP resolution has to defend against.
    allowed_ips: str = field(default_factory=lambda: _env("RM_ALLOWED_IPS", ""))

    def allowed_networks(self) -> list:
        import ipaddress
        nets = []
        for raw in self.allowed_ips.split(","):
            raw = raw.strip()
            if not raw:
                continue
            try:
                nets.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                continue
        return nets

    def peer_allowed(self, peer: str) -> bool:
        """Loopback binding needs no allowlist — nothing off-host can reach it."""
        import ipaddress
        nets = self.allowed_networks()
        if not nets:
            return not self.binds_off_loopback()
        try:
            addr = ipaddress.ip_address(peer)
        except ValueError:
            return False
        return any(addr in n for n in nets)

    def binds_off_loopback(self) -> bool:
        return self.host not in ("127.0.0.1", "localhost", "::1")

    # What it may touch. Named explicitly rather than discovered, so the blast
    # radius is a configuration value someone can read.
    content_bucket: str = field(default_factory=lambda: _env("RM_CONTENT_BUCKET", ""))
    meta_bucket: str = field(default_factory=lambda: _env("RM_META_BUCKET", ""))
    region: str = field(default_factory=lambda: _env("RM_REGION", ""))

    # Credentials come from the environment, and that is the whole of it — no
    # role assumption, no policy machinery. The operator is already signed in to
    # the backup account; they export an administrator credential for the
    # operation and the process ends with it.
    #
    # Deliberately simple. The security property this design rests on is that
    # the DEPLOYMENT cannot reach this application (no inbound path, a human
    # carries the request), not that the credential is elaborately scoped. IAM
    # subtlety here would add configuration to get wrong without changing who
    # can start the operation.
    #
    # What it does ask of the operator, once, in the README: this is a
    # long-lived credential rather than a short-lived assumed role, so it should
    # be exported for the operation and not persisted — not in a dotfile, not in
    # shell history, not in a .env that outlives the afternoon.
    access_key_id: str = field(default_factory=lambda: _env("RM_AWS_ACCESS_KEY_ID", _env("AWS_ACCESS_KEY_ID", "")))
    secret_access_key: str = field(default_factory=lambda: _env("RM_AWS_SECRET_ACCESS_KEY", _env("AWS_SECRET_ACCESS_KEY", "")))

    # Volume limits (§4.3). A normal redaction is a handful of files; thousands
    # is not a busy week, it is an attack or a bug.
    max_objects: int = field(default_factory=lambda: _int("RM_MAX_OBJECTS", 50))
    # The cooling period (§4.4). A statutory erasure deadline is typically a
    # month, so a week costs nothing and turns a silent compromise into
    # something with a window to notice it in.
    hold_days: int = field(default_factory=lambda: _int("RM_HOLD_DAYS", 7))

    def problems(self) -> list[str]:
        """Why this is not safe to operate. Reported rather than raised, so an
        operator sees every gap at once instead of one per attempt."""
        out = []
        if not self.content_bucket:
            out.append("no content bucket configured")
        if not self.meta_bucket:
            out.append("no meta bucket configured — nothing to verify requests against (§4.2)")
        if not (self.access_key_id and self.secret_access_key):
            out.append("no credentials in the environment — nothing can be destroyed, "
                       "which is the safe default")
        if self.binds_off_loopback() and not self.allowed_networks():
            out.append(f"bound off-loopback ({self.host}) with no RM_ALLOWED_IPS — "
                       "bind to loopback and tunnel, or allowlist the administrators")
        if self.allowed_ips and not self.allowed_networks():
            out.append(f"RM_ALLOWED_IPS is set but no entry parsed as a CIDR: {self.allowed_ips!r}")
        if self.max_objects <= 0:
            out.append("max_objects must be positive")
        return out
