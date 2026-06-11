"""2FA backup codes: hashed at rest, single-use, legacy-plaintext compatible.

Regression cover for the hardening that stopped storing backup codes in
plaintext in auth.json (a leaked file otherwise bypassed 2FA directly) and
widened their entropy.
"""
import json

import pytest

from core.auth import AuthManager, _looks_hashed


def _enable_2fa(mgr, username):
    """Drive the real confirm flow and return the plaintext backup codes."""
    secret = mgr.totp_generate_secret(username)
    import pyotp
    code = pyotp.TOTP(secret).now()
    return mgr.totp_confirm_enable(username, code)


def _make_mgr(tmp_path):
    auth_path = tmp_path / "auth.json"
    auth_path.write_text(json.dumps({"users": {}}))
    mgr = AuthManager(str(auth_path))
    mgr.create_user("alice", "pw-correct-horse", is_admin=True)
    return mgr, auth_path


def test_backup_codes_are_hashed_at_rest_and_returned_once(tmp_path):
    mgr, auth_path = _make_mgr(tmp_path)
    plain = _enable_2fa(mgr, "alice")
    assert plain and len(plain) == 8
    # Each code carries real entropy (token_hex(8) -> 16 hex chars).
    assert all(len(c) == 16 for c in plain)
    # Persisted form must be bcrypt hashes, never the plaintext.
    stored = json.loads(auth_path.read_text())["users"]["alice"]["totp_backup_codes"]
    assert all(_looks_hashed(h) for h in stored)
    assert not any(p in stored for p in plain)


def test_backup_code_verifies_and_is_single_use(tmp_path):
    mgr, _ = _make_mgr(tmp_path)
    plain = _enable_2fa(mgr, "alice")
    one = plain[0]
    assert mgr.totp_verify("alice", one) is True
    # Consumed — second use fails.
    assert mgr.totp_verify("alice", one) is False
    # Remaining codes still work.
    assert mgr.totp_verify("alice", plain[1]) is True


def test_wrong_backup_code_rejected(tmp_path):
    mgr, _ = _make_mgr(tmp_path)
    _enable_2fa(mgr, "alice")
    assert mgr.totp_verify("alice", "deadbeefdeadbeef") is False


def test_legacy_plaintext_backup_codes_still_work(tmp_path):
    """Codes stored before hashing was introduced must remain usable."""
    auth_path = tmp_path / "auth.json"
    auth_path.write_text(json.dumps({"users": {
        "bob": {
            "password_hash": "x",
            "totp_enabled": True,
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "totp_backup_codes": ["1234abcd", "5678efgh"],  # legacy plaintext
        },
    }}))
    mgr = AuthManager(str(auth_path))
    assert mgr.totp_verify("bob", "1234abcd") is True
    assert mgr.totp_verify("bob", "1234abcd") is False  # single-use
    assert mgr.totp_verify("bob", "5678efgh") is True
