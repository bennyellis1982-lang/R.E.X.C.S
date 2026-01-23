# R.E.X.C.S
RexCore is the foundational core of the REX system, defining integrity, core state, protection boundaries, and continuity logic. It is intentionally minimal and security first, serving as a stable backbone on which higher order services, agents, and frameworks are built, extended, and governed without compromising system identity.

## Repository layout
- `rex2_client.py`: Device registration + heartbeat client for the REX2.0 service, backed by system keyring secrets.
- `rex2_parser.py`: Lightweight parser for structured REX2.0 text inputs.
- `master_heartbeat.py`: Convenience entry point for repeated heartbeat runs.

## Prerequisites
- Python 3.9+
- Access to a keyring backend supported by your OS (macOS Keychain, Windows Credential Manager, or a Linux secret store).

Install dependencies:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configure the client
Set the REX server URL (defaults to `http://localhost:5001`):
```bash
export REX_SERVER_URL="https://your-rex-server.example"
```

## Register a device + send heartbeats
The first run will generate a device ID, key pair, register with the server, and then send a heartbeat in a short loop.
```bash
python rex2_client.py
```

If you already have a license stored in the keyring, you can trigger heartbeats directly via the helper:
```bash
python master_heartbeat.py
```

## Parse REX2.0 input
Pipe any text payload into the parser to get a structured JSON analysis:
```bash
echo "REX2.0 compliance audit" | python rex2_parser.py
```

## Notes
- Private keys and license JWTs are stored in the system keyring, not the repo.
- If you change keyring backends, remove the saved entries from your OS keychain to re-register cleanly.
