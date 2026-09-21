from jwcrypto import jwk
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass

@dataclass
class KeyRecord:
    #An RSA key pair with key ID (kid), expiry date, and active status
    kid: str
    private_key: rsa.RSAPrivateKey
    expiry: datetime
    active: bool

    #returns true if key is expired "now"
    def expired(self, now: datetime) -> bool:
        return self.expiry <= now

    #serialize public key as a JWK
    def to_jwk(self) -> dict:
        public_key = jwk.JWK.from_pyca(
            self.private_key.public_key()
        )

        result = public_key.export(as_dict=True)

        result["kid"] = self.kid
        result["use"] = "sig"
        result["alg"] = "RS256"

        return result

def generate_key(kid: str, expiry: datetime, active: bool = True) -> KeyRecord:
    #generate active key with unique kid, expiry date
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
    #key store keeps information of all keys
    def __init__(self):
        self.keys: dict[str, KeyRecord] = {}
        now = self.now()
        self.add(generate_key("active-key", now + timedelta(hours=1)))
        self.add(generate_key("expired-key", now - timedelta(hours=1), active=False))

    @staticmethod
    def now() -> datetime:
        return datetime.now(timezone.utc)

    def add(self, key: KeyRecord) -> None:
        self.keys[key.kid] = key

    def get(self, kid: str) -> KeyRecord | None:
        return self.keys.get(kid)

    def get_all(self) -> list[KeyRecord]:
        return list(self.keys.values())

    #return unexpired keys in the record
    def get_unexpired(self, now: datetime) -> list[KeyRecord]:
        return [
            key
            for key in self.keys.values()
            if not key.expired(now)
        ]

    #return active keys
    def get_active(self, now: datetime) -> list[KeyRecord]:
        return [
            key
            for key in self.keys.values()
            if key.active and not key.expired(now)
        ]

    #return expired keys
    def get_expired(self, now: datetime) -> list[KeyRecord]:
        return [
            key
            for key in self.keys.values()
            if key.expired(now)
        ]

    #get active expired key
    def active_key(self, now: datetime) -> KeyRecord:
        active = self.get_active(now)

        if not active:
            raise RuntimeError("No active key")

        return active[0]


    def expired_key(self, now: datetime) -> KeyRecord:
        expired = self.get_expired(now)

        if not expired:
            raise RuntimeError("No expired key")

        return expired[0]

    def get_jwks(self, now: datetime) -> dict:
        return {
            "keys": [
                key.to_jwk()
                for key in self.get_unexpired(now)
            ]
        }
