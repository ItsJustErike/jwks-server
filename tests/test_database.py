import sqlite3
from contextlib import closing
from datetime import timedelta

from jwks_server.database import KeyDatabase
from jwks_server.keys import KeyStore


def test_key_database_persists_private_keys_across_store_instances(tmp_path):
    database = KeyDatabase(tmp_path / "keys.db")
    first_store = KeyStore(database)
    original_key = first_store.get("expired-key")

    reloaded_store = KeyStore(database)
    reloaded_key = reloaded_store.get("expired-key")

    assert original_key is not None
    assert reloaded_key is not None
    assert reloaded_key.private_key.private_numbers() == (
        original_key.private_key.private_numbers()
    )
    assert int(reloaded_key.expiry.timestamp()) == int(original_key.expiry.timestamp())
    assert reloaded_key.active is False


def test_key_database_stores_pkcs1_pem_with_required_expiration_times(tmp_path):
    database_path = tmp_path / "keys.db"
    database = KeyDatabase(database_path)
    store = KeyStore(database)
    now = store.now()

    active_key = store.get("active-key")
    expired_key = store.get("expired-key")

    assert active_key is not None
    assert expired_key is not None
    assert active_key.expiry >= now + timedelta(hours=1)
    assert expired_key.expiry <= now

    with closing(sqlite3.connect(database_path)) as connection:
        private_key_pem = connection.execute(
            "SELECT private_key FROM keys WHERE kid = 'active-key'"
        ).fetchone()[0]

    assert private_key_pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")


def test_key_store_reads_current_expiration_state_from_database(tmp_path):
    database = KeyDatabase(tmp_path / "keys.db")
    store = KeyStore(database)
    expired_key = store.get("expired-key")

    assert expired_key is not None
    expired_key.expiry = store.now() + timedelta(hours=1)
    database.save(expired_key)

    assert "expired-key" in {key["kid"] for key in store.get_jwks(store.now())["keys"]}
    replacement_expired_key = store.expired_key(store.now())
    assert replacement_expired_key.kid != "expired-key"
    assert replacement_expired_key.expiry <= store.now()


def test_key_store_generates_a_new_active_key_after_persisted_key_expires(
    tmp_path,
):
    database = KeyDatabase(tmp_path / "keys.db")
    first_store = KeyStore(database)
    original_active_key = first_store.get("active-key")

    assert original_active_key is not None
    original_active_key.expiry = first_store.now()
    database.save(original_active_key)

    reloaded_store = KeyStore(database)

    assert reloaded_store.get_active(reloaded_store.now())
    assert reloaded_store.get("active-key") is not None
    assert reloaded_store.active_key(reloaded_store.now()).kid != "active-key"
