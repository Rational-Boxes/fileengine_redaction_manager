# Copyright (C) 2026 James Hickman
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Authenticator-style 2FA (TOTP, RFC 6238) for the destructive step.

Implemented against the standard library rather than pulling a dependency. That
is not a general licence to hand-roll crypto: TOTP is HMAC-SHA1 over a counter
plus dynamic truncation, fully specified, with no key agreement and no nonce
management — and this repository's whole posture is that every package added
here is reach granted to the one application that can destroy backup history
(see pyproject). Sixty lines of RFC is the smaller risk.

Two properties matter more than the arithmetic:

* **A code is single-use within its window.** TOTP codes are valid for a step,
  and a verifier that only checks the digits will accept the same code twice
  inside it. That is the classic TOTP flaw, and the one worth defending here:
  the code is taken over an operator's shoulder, or out of a log, and replayed
  a few seconds later against the execute endpoint. `Verifier` refuses any
  counter it has already accepted.
* **Skew is one step, not a generous window.** Each extra step is another code
  an attacker may use. ±1 covers a phone whose clock drifts; ±5 covers nothing
  a correctly-set phone needs.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

STEP_SECONDS = 30
DIGITS = 6
#: Smallest secret accepted, decoded. RFC 4226 requires at least 128 bits and
#: recommends 160. Below this the code space is not the protection it looks
#: like — and an EMPTY secret base32-decodes successfully, so without a floor a
#: blank or whitespace value reads as configured and verifies against a
#: zero-length HMAC key.
MIN_SECRET_BYTES = 16
#: Steps either side of now that are accepted. One, deliberately.
SKEW_STEPS = 1


def _normalise(secret: str) -> bytes:
    """Base32 as an authenticator app presents it: case-insensitive, spaces and
    padding optional, because that is how it arrives when someone types it."""
    s = secret.strip().replace(" ", "").upper()
    s += "=" * (-len(s) % 8)
    return base64.b32decode(s, casefold=True)


def code_for(secret: str, counter: int) -> str:
    key = _normalise(secret)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** DIGITS)).zfill(DIGITS)


def counter_now(at: float | None = None) -> int:
    return int((at if at is not None else time.time()) // STEP_SECONDS)


class Verifier:
    """Stateful because single-use requires state.

    Its state is per-process, which is exactly right for this application: it
    runs on demand for one operation and exits, so there is no replication to
    reason about and no store to keep. If it ever became long-lived or
    replicated, this would need to move — the same trap the platform's
    ReplayGuard header calls out.
    """

    def __init__(self, secret: str):
        self._secret = secret
        self._used: set[int] = set()

    def configured(self) -> bool:
        if not self._secret or not self._secret.strip():
            return False
        try:
            return len(_normalise(self._secret)) >= MIN_SECRET_BYTES
        except Exception:
            return False

    def verify(self, submitted: str, at: float | None = None) -> tuple[bool, str]:
        """(accepted, reason). The reason is for the operator and the audit
        record, never for the caller — a verifier that explains *why* a code
        failed is a verifier that helps someone guess."""
        if not self.configured():
            return False, "no TOTP secret configured"
        submitted = (submitted or "").strip().replace(" ", "")
        if not submitted.isdigit() or len(submitted) != DIGITS:
            return False, "malformed code"

        now = counter_now(at)
        for step in range(-SKEW_STEPS, SKEW_STEPS + 1):
            counter = now + step
            if not hmac.compare_digest(code_for(self._secret, counter), submitted):
                continue
            if counter in self._used:
                # Correct digits, already spent. Refused, and worth saying so
                # distinctly: a replay is a different event from a wrong code
                # and should not be lost among typos in the record.
                return False, "code already used"
            self._used.add(counter)
            return True, "ok"
        return False, "incorrect code"
