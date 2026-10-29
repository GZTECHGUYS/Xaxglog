#!/usr/bin/env python3
"""Sign a declarative module pack with XAXGLOG_PACK_SECRET.

Usage:
  XAXGLOG_PACK_SECRET=... python sdk/sign_pack.py packs/example-pack.json
"""
import hashlib
import hmac
import json
import os
import sys


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: sign_pack.py <manifest.json>")
    secret = os.getenv("XAXGLOG_PACK_SECRET", "")
    if not secret:
        raise SystemExit("XAXGLOG_PACK_SECRET is required")
    with open(sys.argv[1], encoding="utf-8") as fh:
        manifest = json.load(fh)
    digest = hashlib.sha256(canonical(manifest).encode("utf-8")).hexdigest()
    signature = hmac.new(secret.encode("utf-8"), digest.encode("ascii"),
                         hashlib.sha256).hexdigest()
    print(json.dumps({"sha256": digest, "signature": signature}, indent=2))


if __name__ == "__main__":
    main()
