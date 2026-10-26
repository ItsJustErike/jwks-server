# JWKS Server

A RESTful JWKS server using Python, FastAPI, and Uvicorn that:

- Provides public keys with unique identifiers (`kid`) for verifying JWTs.
- Implements key expiry.
- Provides an authentication endpoint.
- Can issue a token using an expired key with the `expired` query parameter.

## Requirements

- Python 3.14 or a compatible Python 3 version.
- PowerShell on Windows, or an equivalent shell for the commands below.

## Set Up the Environment

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, run the commands without activation by replacing `python` with `.\.venv\Scripts\python.exe`.

## Run the Server

```powershell
python -m jwks_server
```

Open the API documentation at <http://localhost:8080/docs>.

## Key Storage

The server stores generated private keys in
`jwks_server/totally_not_my_privateKeys.db` and reuses them after a restart.
The `/auth?expired=true` endpoint signs its token with a stored expired key;
expired keys are not included in the published JWKS. The database is ignored by
Git because it contains unencrypted private keys. Keep the database file
protected and do not commit or share it.

## Run Tests

Run the pytest suite with coverage:

```powershell
python -m pytest
```

The pytest configuration is in `pyproject.toml`. It discovers tests in `tests/`, reports coverage for `jwks_server`, and requires at least 80% total coverage.
