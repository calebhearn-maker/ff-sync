"""ffsync.py - read the encrypted ESPN snapshot that Caleb's PC pushes to GitHub.

Transport: the PC (ff-fetch.ps1) gzips + encrypts a bundle of raw ESPN JSON and
pushes it to a PUBLIC repo. raw.githubusercontent.com is the only GitHub host the
cloud sandbox may read, so that is where we read from. Without the key the files
are noise.

File format (see Protect-FFBytes in ff-lib.ps1):
    b"FFS1" | IV(16) | AES-256-CBC/PKCS7 ciphertext | HMAC-SHA256(32)
    enc key = sha256(master + b"ff-enc"), mac key = sha256(master + b"ff-mac")
    HMAC covers magic + IV + ciphertext.

Usage:
    python3 ffsync.py --owner <gh-user> [--repo ff-sync] --out /tmp/ffdata [--code-out /tmp/ffengine]
    (key from env FF_SYNC_KEY, base64)
The PC also publishes this file in plaintext (ffsync.py at the repo root) and the
engine itself as code.bin, so a fresh cloud session bootstraps with one curl:
    curl -sSf https://raw.githubusercontent.com/<owner>/ff-sync/main/ffsync.py -o ffsync.py
Result: <out>/latest/<name>.json and <out>/weeks/<slug>-wkNN-<view>.json, the same
layout as C:\\FantasyFF, so the engine reads either source identically.
"""
import argparse
import base64
import gzip
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.request

MAGIC = b"FFS1"


def subkeys(master: bytes):
    return (hashlib.sha256(master + b"ff-enc").digest(),
            hashlib.sha256(master + b"ff-mac").digest())


def decrypt(blob: bytes, master: bytes) -> bytes:
    if len(blob) < 4 + 16 + 16 + 32 or blob[:4] != MAGIC:
        raise ValueError("not an ffsync file (bad magic or too short)")
    ek, mk = subkeys(master)
    body, tag = blob[:-32], blob[-32:]
    if not hmac.compare_digest(hmac.new(mk, body, hashlib.sha256).digest(), tag):
        raise ValueError("HMAC mismatch - wrong key, or the file is corrupt/incomplete")
    iv, ct = body[4:20], body[20:]
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        d = Cipher(algorithms.AES(ek), modes.CBC(iv)).decryptor()
        padded = d.update(ct) + d.finalize()
    except ImportError:  # fall back to the openssl CLI
        import subprocess
        padded = subprocess.run(
            ["openssl", "enc", "-d", "-aes-256-cbc", "-nopad", "-K", ek.hex(), "-iv", iv.hex()],
            input=ct, capture_output=True, check=True).stdout
    n = padded[-1]
    if n < 1 or n > 16 or padded[-n:] != bytes([n]) * n:
        raise ValueError("bad padding")
    return gzip.decompress(padded[:-n])


def encrypt(plain_gz: bytes, master: bytes, iv: bytes = None) -> bytes:
    """Python twin of Protect-FFBytes, used by tests."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    ek, mk = subkeys(master)
    iv = iv or os.urandom(16)
    n = 16 - len(plain_gz) % 16
    e = Cipher(algorithms.AES(ek), modes.CBC(iv)).encryptor()
    ct = e.update(plain_gz + bytes([n]) * n) + e.finalize()
    body = MAGIC + iv + ct
    return body + hmac.new(mk, body, hashlib.sha256).digest()


def load_key(key_b64: str = None) -> bytes:
    k = key_b64 or os.environ.get("FF_SYNC_KEY", "")
    if not k:
        raise SystemExit("FF_SYNC_KEY not set")
    b = base64.b64decode(k.strip())
    if len(b) != 32:
        raise SystemExit("FF_SYNC_KEY is not a 32-byte key")
    return b


def fetch(url: str, tries: int = 4) -> bytes:
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ffsync", "Cache-Control": "no-cache"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(3 * (i + 1))
    raise RuntimeError(f"GET {url} failed: {last}")


def unpack_bundle(plain: bytes, out: str, week: int = None):
    b = json.loads(plain.decode("utf-8"))
    if b.get("format") != "ffsync/1":
        raise ValueError(f"unknown bundle format {b.get('format')!r}")
    written = []
    for name, obj in b["files"].items():
        if week is None:
            path = os.path.join(out, "latest", f"{name}.json")
        else:
            slug, view = name.split("-", 1)
            path = os.path.join(out, "weeks", f"{slug}-wk{week:02d}-{view}.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, separators=(",", ":"))
        written.append(path)
    return b.get("meta", {}), written


def unpack_code(plain: bytes, code_out: str):
    """code.bin: {"meta": {"kind": "code", "sha": {name: sha256}}, "files": {name: "<text>"}}.
    Files are written byte-exact and checked against the PC's own hashes."""
    b = json.loads(plain.decode("utf-8"))
    meta = b.get("meta", {})
    shas = {k: str(v).lower() for k, v in (meta.get("sha") or {}).items()}
    os.makedirs(code_out, exist_ok=True)
    written, bad = [], []
    for name, text in b["files"].items():
        if not isinstance(text, str) or "/" in name or "\\" in name or name.startswith("."):
            continue
        data = text.encode("utf-8")
        if shas.get(name) and hashlib.sha256(data).hexdigest() != shas[name]:
            bad.append(name)
        with open(os.path.join(code_out, name), "wb") as f:
            f.write(data)
        written.append(name)
    return meta, written, bad


def sync(owner: str, repo: str, out: str, key: bytes, branch: str = "main", weeks: str = "missing", code_out: str = None):
    """Download manifest + snap.bin (+ week files) and unpack them under `out`.
    Retries when the CDN serves a manifest and a file from different pushes."""
    base = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/"
    report = {"source": base, "files": {}}
    for attempt in range(4):
        manifest = json.loads(fetch(base + "manifest.json").decode("utf-8"))
        snap = fetch(base + "snap.bin")
        want = manifest["files"].get("snap.bin", {}).get("sha256")
        if want and hashlib.sha256(snap).hexdigest() != want:
            report.setdefault("retries", 0)
            report["retries"] += 1
            time.sleep(40)  # raw.githubusercontent.com caches each path up to 5 minutes
            continue
        break
    meta, _ = unpack_bundle(decrypt(snap, key), out)
    report["manifest_updated"] = manifest.get("updated")
    report["snap_meta"] = meta
    os.makedirs(os.path.join(out, "weeks"), exist_ok=True)
    for name, info in sorted(manifest["files"].items()):
        if not name.startswith("wk"):
            continue
        wk = int(name[2:4])
        marker = os.path.join(out, "weeks", f".{name}.{info.get('sha256', '')[:16]}")
        if weeks == "missing" and os.path.exists(marker):
            continue
        blob = fetch(base + name)
        if info.get("sha256") and hashlib.sha256(blob).hexdigest() != info["sha256"]:
            report["files"][name] = "stale-cdn-copy (sha mismatch) - skipped this run"
            continue
        unpack_bundle(decrypt(blob, key), out, week=wk)
        open(marker, "w").close()
        report["files"][name] = "ok"
    if code_out:
        info = manifest["files"].get("code.bin")
        if not info:
            report["code"] = {"status": "no code.bin in the repo yet"}
        else:
            blob = None
            for attempt in range(4):
                blob = fetch(base + "code.bin")
                if not info.get("sha256") or hashlib.sha256(blob).hexdigest() == info["sha256"]:
                    break
                time.sleep(40)
            else:
                blob = None
            if blob is None:
                report["code"] = {"status": "stale-cdn-copy (sha mismatch)"}
            else:
                cmeta, written, bad = unpack_code(decrypt(blob, key), code_out)
                report["code"] = {"status": "ok" if not bad else "hash-mismatch", "files": len(written),
                                  "bad": bad, "created": cmeta.get("created"), "dir": code_out}
    with open(os.path.join(out, "sync-report.json"), "w") as f:
        json.dump(report, f, indent=1)
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--owner", required=True)
    ap.add_argument("--repo", default="ff-sync")
    ap.add_argument("--branch", default="main")
    ap.add_argument("--out", default="/tmp/ffdata")
    ap.add_argument("--weeks", default="missing", choices=["missing", "all"])
    ap.add_argument("--code-out", help="also unpack the engine (code.bin) into this folder")
    a = ap.parse_args()
    rep = sync(a.owner, a.repo, a.out, load_key(), a.branch, a.weeks, a.code_out)
    m = rep.get("snap_meta", {})
    print(json.dumps({"manifest_updated": rep.get("manifest_updated"), "snap_created": m.get("created"),
                      "current": m.get("current"), "espn_ok": m.get("ok"), "espn_fail": m.get("fail"),
                      "weeks": rep.get("files"), "retries": rep.get("retries", 0), "code": rep.get("code")}, indent=1))
    if (rep.get("code") or {}).get("status") == "hash-mismatch":
        return 4


if __name__ == "__main__":
    sys.exit(main())
