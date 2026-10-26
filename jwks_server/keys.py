from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import rsa
from jwcrypto import jwk

from jwks_server.database import KeyDatabase


@dataclass
class KeyRecord:
    # An RSA key pair with key ID (kid), expiry date, and active status
    kid: str
    private_key: rsa.RSAPrivateKey
    expiry: datetime
    active: bool

    # returns true if key is expired "now"
    def expired(self, now: datetime) -> bool:
        return self.expiry <= now

    # serialize public key as a JWK
    def to_jwk(self) -> dict:
        public_key = jwk.JWK.from_pyca(self.private_key.public_key())

        result = public_key.export(as_dict=True)

        result["kid"] = self.kid
        result["use"] = "sig"
        result["alg"] = "RS256"

        return result


def generate_key(kid: str, expiry: datetime, active: bool = True) -> KeyRecord:
    # generate active key with unique kid, expiry date
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    return KeyRecord(
        kid=kid,
        private_key=private_key,
        expiry=expiry,
        active=active,
    )


class KeyStore:
    # key store keeps information of all keys
    def __init__(self, database: KeyDatabase | None = None):
        self.database = database
        self.keys: dict[str, KeyRecord] = {}
        if self.database is not None:
            self.keys = {key.kid: key for key in self.database.load()}

        now = self.now()
        if not self.keys:
            self.add(
                generate_key(
                    "active-key",
                    now + timedelta(hours=1, seconds=1),
                )
            )
            self.add(
                generate_key("expired-key", now - timedelta(hours=1), active=False)
            )
        else:
            long_lived_active = any(
                key.expiry >= now + timedelta(hours=1) for key in self.get_active(now)
            )
            if not long_lived_active:
                self.add(
                    generate_key(
                        self._unique_kid("active-key"),
                        now + timedelta(hours=1, seconds=1),
                    )
                )
            if not self.get_expired(now):
                self.add(
                    generate_key(
                        self._unique_kid("expired-key"),
                        now - timedelta(hours=1),
                        active=False,
                    )
                )

    def _unique_kid(self, prefix: str) -> str:
        kid = f"{prefix}-{uuid4().hex}"
        while kid in self.keys:
            kid = f"{prefix}-{uuid4().hex}"
        return kid

    @staticmethod
    def now() -> datetime:
        return datetime.now(UTC)

    def add(self, key: KeyRecord) -> None:
        self.keys[key.kid] = key
        if self.database is not None:
            self.database.save(key)

    def get(self, kid: str) -> KeyRecord | None:
        return self.keys.get(kid)

    def get_all(self) -> list[KeyRecord]:
        return list(self.keys.values())

    # return unexpired keys in the record
    def get_unexpired(self, now: datetime) -> list[KeyRecord]:
        keys = (
            self.database.load_unexpired(now)
            if self.database is not None
            else self.keys.values()
        )
        return [key for key in keys if not key.expired(now)]

    # return active keys
    def get_active(self, now: datetime) -> list[KeyRecord]:
        keys = (
            self.database.load_unexpired(now)
            if self.database is not None
            else self.keys.values()
        )
        return [key for key in keys if key.active and not key.expired(now)]

    # return expired keys
    def get_expired(self, now: datetime) -> list[KeyRecord]:
        keys = (
            self.database.load_expired(now)
            if self.database is not None
            else self.keys.values()
        )
        return [key for key in keys if key.expired(now)]

    # get active expired key
    def active_key(self, now: datetime) -> KeyRecord:
        active = self.get_active(now)

        if not active:
            if self.database is not None:
                key = generate_key(
                    self._unique_kid("active-key"),
                    now + timedelta(hours=1, seconds=1),
                )
                self.add(key)
                return key
            raise RuntimeError("No active key")

        return active[0]

    def expired_key(self, now: datetime) -> KeyRecord:
        expired = self.get_expired(now)

        if not expired:
            if self.database is not None:
                key = generate_key(
                    self._unique_kid("expired-key"),
                    now - timedelta(seconds=1),
                    active=False,
                )
                self.add(key)
                return key
            raise RuntimeError("No expired key")

        return expired[0]

    def get_jwks(self, now: datetime) -> dict:
        return {"keys": [key.to_jwk() for key in self.get_unexpired(now)]}
