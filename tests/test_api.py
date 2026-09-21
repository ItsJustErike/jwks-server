import base64
import json

from fastapi.testclient import TestClient
from jwcrypto import jwk, jwt

from jwks_server.app import create_app


client = TestClient(create_app())

def test_jwks_endpoint_publishes_only_unexpired_public_keys():
    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200
    keys = response.json()["keys"]
    assert len(keys) == 1
    assert keys[0]["kid"] == "active-key"
    assert "d" not in keys[0]

def test_openapi_endpoint_is_available():
    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert "/auth" in response.json()["paths"]

def test_auth_returns_a_verifiable_active_token():
    jwks = client.get("/.well-known/jwks.json").json()
    response = client.post("/auth")

    assert response.status_code == 200
    public_key = jwk.JWK(**jwks["keys"][0])
    verified = jwt.JWT(key=public_key, jwt=response.text)
    claims = json.loads(verified.claims)
    assert claims["sub"] == "user"
    assert verified.token.jose_header["kid"] == "active-key"

def test_auth_expired_mode_returns_an_expired_token():
    response = client.post("/auth?expired=true")

    assert response.status_code == 200
    claims = json.loads(_decode_payload(response.text))
    assert claims["exp"] < claims["iat"]

def _decode_payload(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return base64.urlsafe_b64decode(payload).decode("utf-8")
