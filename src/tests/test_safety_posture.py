# Copyright (C) 2026 James Hickman
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The properties that must hold before this application may operate at all.

Written first, and deliberately: this is the only component in the estate that
can destroy backup history, and the conditions under which it may run should be
settled before anything it can do exists.
"""
import pathlib

from fastapi.testclient import TestClient

from redaction_manager.app import build_app
from redaction_manager.config import Config


def _cfg(**over) -> Config:
    c = Config()
    c.content_bucket = "fe-content-backup"
    c.meta_bucket = "fe-meta-backup"
    c.access_key_id = "AKIAEXAMPLE"
    c.secret_access_key = "secret"
    c.second_factor = "totp"
    c.totp_secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    c.host = "127.0.0.1"
    for k, v in over.items():
        setattr(c, k, v)
    return c


def test_ready_when_configured():
    r = TestClient(build_app(_cfg())).get("/readyz")
    assert r.status_code == 200


def test_without_credentials_it_is_not_ready():
    # And that is the safe direction: with no credential in the environment,
    # nothing can be destroyed.
    r = TestClient(build_app(_cfg(access_key_id="", secret_access_key=""))).get("/readyz")
    assert r.status_code == 503
    assert any("credentials" in p for p in r.json()["problems"])


def test_without_the_meta_bucket_it_cannot_verify_and_refuses():
    # §4.2: requests are verified against the retained chain. Without it the
    # human would be approving unverifiable rows, which is a rubber stamp.
    r = TestClient(build_app(_cfg(meta_bucket=""))).get("/readyz")
    assert r.status_code == 503
    assert any("verify" in p for p in r.json()["problems"])


def test_off_loopback_without_an_allowlist_is_refused():
    # The one combination never intended, and exactly what a hurried
    # "it wasn't reachable from my laptop" change produces.
    r = TestClient(build_app(_cfg(host="0.0.0.0"))).get("/readyz")
    assert r.status_code == 503
    assert any("RM_ALLOWED_IPS" in p for p in r.json()["problems"])


def test_off_loopback_with_an_allowlist_is_allowed():
    c = _cfg(host="0.0.0.0", allowed_ips="203.0.113.7/32, 198.51.100.0/24")
    assert TestClient(build_app(c)).get("/readyz").status_code == 200


def test_a_malformed_allowlist_is_refused_rather_than_ignored():
    # An unparseable allowlist that silently admitted everyone would be the
    # worst outcome: it reads as configured and enforces nothing.
    c = _cfg(host="0.0.0.0", allowed_ips="not-an-address")
    r = TestClient(build_app(c)).get("/readyz")
    assert r.status_code == 503
    assert any("CIDR" in p for p in r.json()["problems"])


def test_peer_matching():
    c = _cfg(host="0.0.0.0", allowed_ips="203.0.113.7/32,198.51.100.0/24")
    assert c.peer_allowed("203.0.113.7")
    assert c.peer_allowed("198.51.100.42")
    assert not c.peer_allowed("203.0.113.8")
    assert not c.peer_allowed("not-an-ip")
    # With a loopback bind and no allowlist, nothing off-host can reach it, so
    # the check is not what is protecting anything.
    assert _cfg().peer_allowed("127.0.0.1")


def test_no_operation_routes_exist_yet():
    paths = {r.path for r in build_app(_cfg()).routes}
    assert paths & {"/healthz", "/readyz"}
    assert not any(p.startswith(("/upload", "/verify", "/execute", "/approve")) for p in paths)


def test_it_has_no_route_to_the_deployment():
    """Structural, not aspirational. The absence of these packages is what makes
    'no inbound path from cloud A' a property rather than a promise, so it is
    asserted rather than left to review."""
    import tomllib
    # Parse the declared dependencies rather than grepping the file: the
    # pyproject comment names these packages precisely to explain why they are
    # absent, and a text search would match the explanation.
    data = tomllib.loads((pathlib.Path(__file__).parents[2] / "pyproject.toml").read_text())
    declared = " ".join(data["project"]["dependencies"]).lower()
    for forbidden in ("grpcio", "python-interface", "python_interface", "ldap3", "redis", "psycopg"):
        assert forbidden not in declared, \
            f"{forbidden} would give this reach into the deployment"


def test_a_password_alone_is_never_enough():
    # The requirement, as an invariant: with no second factor configured the
    # deployment is not ready, rather than falling back to the password.
    r = TestClient(build_app(_cfg(second_factor=""))).get("/readyz")
    assert r.status_code == 503
    assert any("second factor" in p for p in r.json()["problems"])


def test_a_factor_this_build_cannot_verify_fails_closed():
    # webauthn is accepted configuration and is not implemented. A build
    # configured for it must refuse, not accept something weaker — which is
    # this platform's characteristic failure and least acceptable here.
    r = TestClient(build_app(_cfg(second_factor="webauthn"))).get("/readyz")
    assert r.status_code == 503
    assert any("not implemented" in p for p in r.json()["problems"])


def test_an_unknown_factor_is_refused():
    r = TestClient(build_app(_cfg(second_factor="magic"))).get("/readyz")
    assert r.status_code == 503
    assert any("unknown second factor" in p for p in r.json()["problems"])


def test_totp_configured_without_a_usable_secret_is_refused():
    for bad in ("", "   ", "SHORT"):
        r = TestClient(build_app(_cfg(totp_secret=bad))).get("/readyz")
        assert r.status_code == 503, bad
        assert any("secret is missing or too short" in p for p in r.json()["problems"])


def test_hardware_key_alongside_totp_still_fails_until_implemented():
    # Configuring both must not let the implemented one paper over the other:
    # an operator who registered a YubiKey would reasonably believe it was
    # being checked.
    r = TestClient(build_app(_cfg(second_factor="totp,webauthn"))).get("/readyz")
    assert r.status_code == 503
    assert any("webauthn" in p for p in r.json()["problems"])
