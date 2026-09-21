from datetime import datetime, timezone
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from jwcrypto import jwk, jwt
from jwks_server.keys import KeyStore


def issue_token(record, now: datetime, expired: bool = False) -> str:
    expiration = record.expiry
    if not expired and expiration <= now:
        raise RuntimeError("Cannot issue a token with an expired key")

    claims = {
        "sub": "user",
        "iat": int(now.timestamp()),
        "exp": int(expiration.timestamp()),
    }
    token = jwt.JWT(
        header={"alg": "RS256", "kid": record.kid},
        claims=claims,
    )
    token.make_signed_token(jwk.JWK.from_pyca(record.private_key))
    return token.serialize()


def create_app() -> FastAPI:
    #Build application
    app = FastAPI()
    key_store = KeyStore()

    #serve the public keys that have not expired yet
    @app.get("/.well-known/jwks.json")
    def jwks():
        now = datetime.now(timezone.utc)
        return key_store.get_jwks(now)

    #/auth endpoint that returns unexpired signed JWT on POST request
    @app.post("/auth", response_class=PlainTextResponse)
    def auth(request: Request) -> str:
        now = key_store.now()
        expired = "expired" in request.query_params

        record = (
            key_store.expired_key(now)
            if expired
            else key_store.active_key(now)
        )

        return issue_token(record, now, expired=expired)

    return app

