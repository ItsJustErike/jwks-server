import base64
import json

import pytest
from fastapi.testclient import TestClient
from jwcrypto import jwk, jws, jwt

from jwks_server.app import create_app
from jwks_server.database import KeyDatabase


@pytest.fixture
def key_database(tmp_path):
    return KeyDatabase(tmp_path / "keys.db")


@pytest.fixture
def client(key_database):
    return TestClient(create_app(key_database))


def test_jwks_endpoint_publishes_only_unexpired_public_keys(client):
    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200
    keys = response.json()["keys"]
    assert len(keys) == 1
    assert keys[0]["kid"] == "active-key"
    assert "d" not in keys[0]


def test_openapi_endpoint_is_available(client):
    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert "/auth" in response.json()["paths"]


def test_auth_returns_a_verifiable_active_token(client):
    jwks = client.get("/.well-known/jwks.json").json()
    response = client.post("/auth")

    assert response.status_code == 200
    public_key = jwk.JWK(**jwks["keys"][0])
    verified = jwt.JWT(key=public_key, jwt=response.text)
    claims = json.loads(verified.claims)
    assert claims["sub"] == "user"
    assert verified.token.jose_header["kid"] == "active-key"


def test_auth_expired_mode_returns_a_persisted_expired_token(client, key_database):
    response = client.post("/auth?expired=true")

    assert response.status_code == 200
    claims = json.loads(_decode_payload(response.text))
    assert claims["exp"] < claims["iat"]
    expired_key = next(key for key in key_database.load() if key.kid == "expired-key")
    verified = jws.JWS()
    verified.deserialize(response.text)
    verified.verify(jwk.JWK.from_pyca(expired_key.private_key.public_key()))
    assert verified.jose_header["kid"] == "expired-key"


def _decode_payload(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return base64.urlsafe_b64decode(payload).decode("utf-8")
