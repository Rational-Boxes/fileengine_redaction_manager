# Copyright (C) 2026 James Hickman
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""A second factor is mandatory here, and a password is not one.

This application can destroy backup history. A username and password is a
single reusable secret that can be phished, reused from another breach, or read
over a shoulder, and no amount of length policy changes that. So an operator
presents a password *and* a second factor, and the second factor is a device:
an authenticator app, or a hardware security key.

**The discipline this module exists to enforce is that an unimplemented method
fails closed.** A configuration naming a factor the build cannot actually verify
must refuse to operate — not accept the password alone, not skip the step, not
log a warning and continue. That failure mode is this platform's characteristic
one (a stub that reports success), and it is least acceptable here.
"""
from __future__ import annotations

from dataclasses import dataclass

from .twofa import Verifier as TotpVerifier

#: Methods this build can actually verify.
IMPLEMENTED = ("totp",)
#: Methods that are accepted configuration but not yet verifiable. Naming them
#: is deliberate: a typo should be an unknown method, while a genuine
#: not-yet-built one should say so precisely.
DECLARED_NOT_IMPLEMENTED = ("webauthn",)


@dataclass
class SecondFactor:
    """What the deployment configured, and whether it can be honoured."""
    methods: tuple[str, ...]
    totp: TotpVerifier | None = None

    @classmethod
    def from_config(cls, methods: str, totp_secret: str) -> "SecondFactor":
        parsed = tuple(m.strip().lower() for m in methods.split(",") if m.strip())
        return cls(methods=parsed,
                   totp=TotpVerifier(totp_secret) if "totp" in parsed else None)

    def problems(self) -> list[str]:
        out: list[str] = []
        if not self.methods:
            out.append("no second factor configured — a password alone is not "
                       "sufficient for this level of access")
            return out

        for m in self.methods:
            if m in IMPLEMENTED:
                continue
            if m in DECLARED_NOT_IMPLEMENTED:
                # Fails CLOSED. A build that cannot verify webauthn must not
                # run configured for it and quietly accept something weaker.
                out.append(f"second factor '{m}' is configured but not implemented "
                           "in this build — it cannot be verified, so it must not "
                           "be relied on")
            else:
                out.append(f"unknown second factor '{m}'")

        if "totp" in self.methods and (self.totp is None or not self.totp.configured()):
            out.append("TOTP is configured as a second factor but its secret is "
                       "missing or too short")
        return out

    def usable(self) -> bool:
        return not self.problems()

    def verify(self, method: str, credential: str, at: float | None = None) -> tuple[bool, str]:
        method = (method or "").strip().lower()
        if method not in self.methods:
            return False, "method not enabled"
        if method == "totp":
            if self.totp is None:
                return False, "totp not configured"
            return self.totp.verify(credential, at=at)
        # Reached only for a method that passed problems(), which by
        # construction cannot happen — but returning False here rather than
        # raising means a future method added to IMPLEMENTED without a branch
        # refuses rather than silently succeeds.
        return False, f"no verifier for '{method}'"
