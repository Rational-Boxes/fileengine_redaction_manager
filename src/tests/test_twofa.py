# Copyright (C) 2026 James Hickman
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""TOTP, and specifically the two ways a TOTP verifier is usually wrong."""
import pytest

from redaction_manager.twofa import STEP_SECONDS, Verifier, code_for, counter_now

# 32 base32 chars = 160 bits. The RFC's usual example ("JBSWY3DPEHPK3PXP") is
# 80 bits and is deliberately REJECTED by MIN_SECRET_BYTES — below 128 bits the
# code space is not the protection it looks like, and this guards the
# destruction of backup history.
SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


def test_accepts_the_current_code():
    now = 1_700_000_000.0
    v = Verifier(SECRET)
    ok, why = v.verify(code_for(SECRET, counter_now(now)), at=now)
    assert ok, why


def test_rejects_a_wrong_code():
    now = 1_700_000_000.0
    v = Verifier(SECRET)
    bad = "000000" if code_for(SECRET, counter_now(now)) != "000000" else "111111"
    ok, why = v.verify(bad, at=now)
    assert not ok and why == "incorrect code"


def test_a_code_cannot_be_replayed_within_its_window():
    # THE test. A verifier that only checks digits accepts the same code twice
    # inside its step — which is how a code read over a shoulder, or out of a
    # log, gets used against the execute endpoint seconds later.
    now = 1_700_000_000.0
    v = Verifier(SECRET)
    code = code_for(SECRET, counter_now(now))
    assert v.verify(code, at=now)[0]
    ok, why = v.verify(code, at=now + 1)
    assert not ok
    assert why == "code already used", "a replay must be distinguishable from a typo"


def test_skew_is_one_step_either_way_and_no_more():
    now = 1_700_000_000.0
    c = counter_now(now)
    assert Verifier(SECRET).verify(code_for(SECRET, c - 1), at=now)[0]
    assert Verifier(SECRET).verify(code_for(SECRET, c + 1), at=now)[0]
    # Two steps out is a clock that needs fixing, not a window to widen: each
    # extra step is another code an attacker may use.
    assert not Verifier(SECRET).verify(code_for(SECRET, c - 2), at=now)[0]
    assert not Verifier(SECRET).verify(code_for(SECRET, c + 2), at=now)[0]


@pytest.mark.parametrize("bad", ["", "   ", "12345", "1234567", "abcdef", None])
def test_malformed_codes_are_refused_without_comparing(bad):
    ok, why = Verifier(SECRET).verify(bad, at=1_700_000_000.0)
    assert not ok and why == "malformed code"


def test_unconfigured_never_accepts():
    # The safe direction: with no secret, nothing verifies, so nothing proceeds.
    for secret in ("", "   ", "not-base32!!"):
        v = Verifier(secret)
        assert not v.configured()
        assert not v.verify("123456", at=1_700_000_000.0)[0]


def test_secret_is_accepted_as_an_authenticator_app_presents_it():
    # Lowercase, spaced, unpadded — how it arrives when someone types it.
    now = 1_700_000_000.0
    spaced = "jbsw y3dp ehpk 3pxp jbsw y3dp ehpk 3pxp"
    assert Verifier(spaced).verify(code_for(SECRET, counter_now(now)), at=now)[0]


def test_codes_change_between_steps():
    c = counter_now(1_700_000_000.0)
    assert code_for(SECRET, c) != code_for(SECRET, c + 1)
    assert STEP_SECONDS == 30


def test_a_secret_below_the_floor_is_refused():
    # 80 bits, as several authenticator setups still hand out. Accepted widely
    # and not here: this verifier stands in front of irreversible deletion.
    v = Verifier("JBSWY3DPEHPK3PXP")
    assert not v.configured()
    assert not v.verify("123456", at=1_700_000_000.0)[0]


def test_whitespace_is_not_a_secret():
    # It base32-decodes successfully to zero bytes, so without a length floor
    # it reads as configured and verifies against an empty HMAC key. Found by
    # this test, not by review.
    assert not Verifier("   ").configured()
