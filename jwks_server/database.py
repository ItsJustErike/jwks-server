import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

if TYPE_CHECKING:
    from jwks_server.keys import KeyRecord


class KeyDatabase:
    def __init__(self, path: str | Path | None = None):
        self.path = (
            Path(path)
            if path is not None
            else Path(__file__).with_name("totally_not_my_privateKeys.db")
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)

        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS keys (
                    kid TEXT PRIMARY KEY,
                    private_key BLOB NOT NULL,
                    expiry INTEGER NOT NULL,
                    active INTEGER NOT NULL
                )
                """
            )

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        connection = sqlite3.connect(self.path)
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def load(self) -> list["KeyRecord"]:
        return self._load_records()

    def load_unexpired(self, now: datetime) -> list["KeyRecord"]:
        return self._load_records(
            "WHERE expiry > ?",
            (int(now.timestamp()),),
        )

    def load_expired(self, now: datetime) -> list["KeyRecord"]:
        return self._load_records(
            "WHERE expiry <= ?",
            (int(now.timestamp()),),
        )

    def _load_records(
        self,
        where_clause: str = "",
        parameters: tuple[int, ...] = (),
    ) -> list["KeyRecord"]:
        from jwks_server.keys import KeyRecord

        with self._connection() as connection:
            rows = connection.execute(
                "SELECT kid, private_key, expiry, active FROM keys "
                f"{where_clause} ORDER BY kid",
                parameters,
            ).fetchall()

        records = []
        for kid, private_key_pem, expiry, active in rows:
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
            )
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise TypeError(f"Stored key {kid!r} is not an RSA private key")

            records.append(
                KeyRecord(
                    kid=kid,
                    private_key=private_key,
                    expiry=datetime.fromtimestamp(expiry, UTC),
                    active=bool(active),
                )
            )
        return records

    def save(self, record: "KeyRecord") -> None:
        private_key_pem = record.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO keys (kid, private_key, expiry, active)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(kid) DO UPDATE SET
                    private_key = excluded.private_key,
                    expiry = excluded.expiry,
                    active = excluded.active
                """,
                (
                    record.kid,
                    private_key_pem,
                    int(record.expiry.timestamp()),
                    record.active,
                ),
            )
