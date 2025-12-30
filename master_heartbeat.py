#!/usr/bin/env python3
"""
master_heartbeat.py (improved)
- POSIX file locking for append/read
- robust last-hash retrieval
- optional HMAC tamper-evidence (ENV: HEARTBEAT_HMAC_KEY)
- concurrent recall via ThreadPoolExecutor (supports SilkSheet threads)
- placeholders for Dropbox/GitHub/crypto/OpenAI/Rex2.0 recall logic
"""

import os
import json
import hashlib
import threading
import datetime
import yaml
from typing import Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# POSIX locking
import fcntl

# Optional libs
try:
    import requests
except Exception:
    requests = None

# Keep optional integrations guarded
try:
    import dropbox
except Exception:
    dropbox = None
try:
    from github import Github
except Exception:
    Github = None

ROOT_DIR = os.path.expanduser("~/MasterVault_333")
HEARTBEAT_FILE = os.path.join(ROOT_DIR, "heartbeat_log.jsonl")
CONFIG_FILE = os.path.join(ROOT_DIR, "config.yaml")
AGENT_ID = "Rex-PhoenixCore-333"

DEFAULT_INTERVAL = 300  # seconds

def ensure_dirs():
    os.makedirs(ROOT_DIR, exist_ok=True)
    os.makedirs(os.path.join(ROOT_DIR, "recalls"), exist_ok=True)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def hmac_hex(key: bytes, message: str) -> str:
    import hmac
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()

def load_config() -> Dict[str, Any]:
    if not os.path.exists(CONFIG_FILE):
        return {}
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def read_last_full_line(path: str, max_bytes=65536) -> Optional[str]:
    """
    Read from file end up to max_bytes and return last full line (str) or None.
    """
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_SH)
            f.seek(0, os.SEEK_END)
            file_size = f.tell()
            to_read = min(file_size, max_bytes)
            f.seek(file_size - to_read)
            data = f.read().decode("utf-8", errors="ignore")
            lines = data.strip().splitlines()
            return lines[-1] if lines else None
        finally:
            try:
                fcntl.flock(f, fcntl.LOCK_UN)
            except Exception:
                pass

def last_heartbeat_hash() -> str:
    last_line = read_last_full_line(HEARTBEAT_FILE)
    if not last_line:
        return ""
    try:
        obj = json.loads(last_line)
        return obj.get("entry_hash", "")
    except Exception:
        return ""

def write_heartbeat_entry(entry: Dict[str, Any], hmac_key: Optional[bytes]=None):
    # compute canonical JSON without entry_hash/hmac
    entry_copy = dict(entry)  # shallow copy
    # ensure deterministic ordering for hash
    entry_json = json.dumps(entry_copy, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    entry_hash = sha256_hex(entry_json)
    entry_copy["entry_hash"] = entry_hash
    if hmac_key:
        entry_copy["hmac"] = hmac_hex(hmac_key, entry_json)
    # Append with exclusive lock
    os.makedirs(os.path.dirname(HEARTBEAT_FILE), exist_ok=True)
    with open(HEARTBEAT_FILE, "a+", encoding="utf-8") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(json.dumps(entry_copy, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        finally:
            try:
                fcntl.flock(f, fcntl.LOCK_UN)
            except Exception:
                pass

# --- Node checkers ---

def check_dropbox_status(token: str):
    if not dropbox:
        return {"status": "lib_missing"}
    try:
        dbx = dropbox.Dropbox(token, timeout=10)
        res = dbx.users_get_current_account()
        return {"status": "ok", "account_email": res.email}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def check_github_status(token: str):
    if not Github:
        return {"status": "lib_missing"}
    try:
        gh = Github(token, timeout=10)
        return {"status": "ok", "login": gh.get_user().login}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def check_http(endpoint: str, timeout=8):
    if not requests:
        return {"status": "lib_missing"}
    try:
        r = requests.get(endpoint, timeout=timeout)
        return {"status": "ok", "code": r.status_code}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def recall_node(node: Dict[str, Any], config: Dict[str, Any]):
    """
    Real implementations should:
      - Dropbox: list and optionally download verified copies of designated files
      - GitHub: fetch repo metadata or archive tarball
      - crypto_rpc: call RPC for status, block height, peers
      - rex2.0/live_network: call internal endpoint for memory snapshot
      - openai/gpt: perform analysis of metadata (not raw secrets)
    This placeholder writes a basic meta.json to recalls/<node_id>
    """
    node_dir = os.path.join(ROOT_DIR, "recalls", node.get("id", node.get("name", "unknown")))
    os.makedirs(node_dir, exist_ok=True)
    meta = {"node": node, "fetched_at": datetime.datetime.utcnow().isoformat() + "Z"}
    # implement per-type fetch if required
    with open(os.path.join(node_dir, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    return {"status": "recalled", "node_id": node.get("id")}

def gather_node_statuses(config):
    statuses = {}
    for node in config.get("nodes", []):
        nid = node.get("id") or node.get("name")
        typ = node.get("type")
        if typ == "dropbox":
            statuses[nid] = check_dropbox_status(config.get("dropbox_token", ""))
        elif typ == "github":
            statuses[nid] = check_github_status(config.get("github_token", ""))
        elif typ == "http":
            statuses[nid] = check_http(node.get("endpoint"))
        elif typ == "crypto_rpc":
            # for production, implement real RPC call
            statuses[nid] = check_http(node.get("endpoint"))
        elif typ in ("rex2.0", "live_network", "gpt"):
            statuses[nid] = check_http(node.get("endpoint"))
        else:
            statuses[nid] = {"status": "unknown_type", "type": typ}
    return statuses

def heartbeat_once(config, hmac_key: Optional[bytes]=None):
    prev_hash = last_heartbeat_hash()
    statuses = gather_node_statuses(config)
    entry = {
        "utc_time": datetime.datetime.utcnow().isoformat() + "Z",
        "agent_id": AGENT_ID,
        "prev_hash": prev_hash,
        "directive": "MASTER_DEFAULT_ROLLING_MEMORY_HEARTBEAT_THREAD / Phoenix core 333",
        "node_statuses": statuses,
        "silk_sheet_threads": config.get("silk_sheet_threads", 1)
    }
    write_heartbeat_entry(entry, hmac_key)

    # Concurrent recall for nodes flagged for recall_on_heartbeat
    silk_threads = int(config.get("silk_sheet_threads", 4))
    recall_nodes = [n for n in config.get("nodes", []) if n.get("recall_on_heartbeat")]
    if recall_nodes:
        with ThreadPoolExecutor(max_workers=min(700, silk_threads)) as ex:
            futures = {ex.submit(recall_node, n, config): n for n in recall_nodes}
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as e:
                    # write error heartbeat for recall failure
                    err = {
                        "utc_time": datetime.datetime.utcnow().isoformat() + "Z",
                        "agent_id": AGENT_ID,
                        "error_recall": str(e),
                        "node": futures[fut].get("id")
                    }
                    write_heartbeat_entry(err, hmac_key)

def heartbeat_loop(interval_seconds, stop_event, config, hmac_key: Optional[bytes]):
    while not stop_event.is_set():
        try:
            heartbeat_once(config, hmac_key=hmac_key)
        except Exception as e:
            err_entry = {
                "utc_time": datetime.datetime.utcnow().isoformat() + "Z",
                "agent_id": AGENT_ID,
                "error": str(e)
            }
            write_heartbeat_entry(err_entry, hmac_key)
        stop_event.wait(interval_seconds)

def main():
    ensure_dirs()
    config = load_config()
    # HMAC key: ENV preferred. Alternatively expand to keychain.
    hmac_key_env = os.environ.get("HEARTBEAT_HMAC_KEY")
    hmac_key = hmac_key_env.encode("utf-8") if hmac_key_env else None

    stop_event = threading.Event()
    interval = int(config.get("interval_seconds", DEFAULT_INTERVAL))
    silk_threads = int(config.get("silk_sheet_threads", 4))

    t = threading.Thread(target=heartbeat_loop, args=(interval, stop_event, config, hmac_key), daemon=True)
    t.start()
    print(f"Master heartbeat started. interval={interval}s silk_threads={silk_threads}. Press Ctrl-C to stop.")
    try:
        while t.is_alive():
            t.join(1)
    except KeyboardInterrupt:
        print("Stopping heartbeat...")
        stop_event.set()
        t.join()

if __name__ == "__main__":
    main()
