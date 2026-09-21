from datetime import timedelta

import pytest
from jwks_server.keys import KeyStore, generate_key


def test_generated_key_has_expected_public_jwk_metadata():
    store = KeyStore()
    key = store.get("active-key")

    assert key is not None
    public_jwk = key.to_jwk()
    assert public_jwk["kid"] == "active-key"
    assert public_jwk["alg"] == "RS256"
    assert public_jwk["use"] == "sig"
    assert "d" not in public_jwk

def test_store_separates_active_and_expired_keys():
    store = KeyStore()
    now = store.now()

    assert [key.kid for key in store.get_active(now)] == ["active-key"]
    assert [key.kid for key in store.get_expired(now)] == ["expired-key"]
    assert [key.kid for key in store.get_unexpired(now)] == ["active-key"]

def test_store_raises_when_requested_key_type_is_missing():
    store = KeyStore()
    now = store.now()
    store.keys.clear()

    with pytest.raises(RuntimeError, match="No active key"):
        store.active_key(now)
    with pytest.raises(RuntimeError, match="No expired key"):
        store.expired_key(now)

def test_generate_key_can_create_inactive_unexpired_key():
    store = KeyStore()
    key = generate_key("standby-key", store.now() + timedelta(hours=1), active=False)
    store.add(key)

    assert store.get("standby-key") == key
    assert key not in store.get_active(store.now())
    assert key in store.get_unexpired(store.now())
