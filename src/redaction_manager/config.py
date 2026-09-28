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
    # The review UI binds LOOPBACK-ONLY and is not negotiable. This application
    # is started by an operator already signed in to the backup account, for one
    # operation; a listener reachable off-host is a standing deletion surface.
    host: str = field(default_factory=lambda: _env("RM_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _int("RM_PORT", 8105))

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
        if self.host not in ("127.0.0.1", "localhost", "::1"):
            out.append(f"review UI bound off-loopback ({self.host}) — this must not be reachable")
        if self.max_objects <= 0:
            out.append("max_objects must be positive")
        return out
