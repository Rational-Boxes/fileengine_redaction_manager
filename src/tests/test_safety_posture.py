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


def test_the_review_ui_must_be_loopback():
    r = TestClient(build_app(_cfg(host="0.0.0.0"))).get("/readyz")
    assert r.status_code == 503
    assert any("loopback" in p for p in r.json()["problems"])


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
