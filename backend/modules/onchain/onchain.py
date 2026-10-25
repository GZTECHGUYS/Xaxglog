"""Xaxglog onchain — ENS names + NFT/transfer pivots on public chains.

Keyless core:
  - ENS resolution via public L2/Eth JSON-RPC-free HTTP resolver:
    Cloudflare Ethereum gateway (cloudflare-eth.com) for eth_call into the
    ENS Universal Resolver, plus reverse-resolution. All public RPC.
  - ETH balance + native tx count via the same public gateway (JSON-RPC).
  - NFT holdings: public NFT marketplace API without key is unreliable,
    so the module uses the free OpenSea v2 endpoints when OPENSEA_API_KEY
    is set and degrades honestly otherwise.

Complements crypto (BTC/ETH 1-hop fund flow via Esplora) with the *name*
axis: ENS -> address -> holdings; used to anchor handles to wallets.

Lawful-use note: public chain state only. No private-key material ever
accepted; reads-only JSON-RPC.
"""
import json
import re

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0", "Content-Type": "application/json"}
T = 20
RPC = "https://cloudflare-eth.com"
ENS_REGISTRY = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"
ADDR = re.compile(r"^0x[a-fA-F0-9]{40}$")


def _rpc(method, params):
    import requests
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    r = requests.post(RPC, headers=UA, json=body, timeout=T)
    if r.status_code != 200:
        raise RuntimeError(f"RPC HTTP {r.status_code}")
    j = r.json()
    if j.get("error"):
        raise RuntimeError(str(j["error"])[:150])
    return j.get("result")


def resolve_ens(name):
    """ENS name -> address via Cloudflare ETH gateway (keyless eth_call)."""
    try:
        name = (name or "").strip()
        if not name or " " in name:
            return {"status": "error", "error": "invalid ENS name"}
        if ADDR.match(name):
            return {"status": "ok", "input": name, "address": name,
                    "note": "input was already an address"}
        # resolver(addr) via registry: namehash is keccak-based — use the
        # public ENS universal resolver endpoint through mainnet RPC instead:
        # eth_call resolver(bytes) is heavy; use the well-known public HTTP
        # resolver maintained by ensdata-style mirrors, fall back to RPC
        import requests
        try:
            r = requests.get(f"https://api.ensideas.com/ens/resolve/{name}",
                             headers=UA, timeout=T)
            if r.status_code == 200:
                j = r.json()
                if j.get("address"):
                    return {"status": "ok", "input": name,
                            "address": j["address"],
                            "reverse_name": j.get("name"),
                            "avatar": j.get("avatar"),
                            "source": "ensideas"}
        except Exception:
            pass
        # fallback: registry addr(namehash) needs keccak — try pycryptodome
        try:
            from Crypto.Hash import keccak  # pycryptodome (optional dep)
        except ImportError:
            return {"status": "unconfigured",
                    "error": "ENS resolver mirror unavailable and pycryptodome "
                             "not installed (pip install pycryptodome)"}

        def namehash(n):
            node = b"\x00" * 32
            for label in reversed(n.split(".")):
                k = keccak.new(digest_bits=256)
                k.update(label.encode())
                k2 = keccak.new(digest_bits=256)
                k2.update(k.digest() + node)
                node = k2.digest()
            return "0x" + node.hex()

        def ens_call(data):
            return _rpc("eth_call", [{"to": ENS_REGISTRY, "data": data}, "latest"])

        resolver = ens_call("0x0178b8bf" + namehash(name)[2:].rjust(64, "0"))
        resolver_addr = "0x" + resolver[-40:]
        if int(resolver_addr, 16) == 0:
            return {"status": "notfound", "input": name,
                    "note": "no resolver set for this name"}
        addr_data = "0x3b3b57de" + namehash(name)[2:].rjust(64, "0")
        res = _rpc("eth_call", [{"to": resolver_addr, "data": addr_data}, "latest"])
        addr = "0x" + res[-40:]
        if int(addr, 16) == 0:
            return {"status": "notfound", "input": name,
                    "note": "resolver returns no address"}
        return {"status": "ok", "input": name, "address": addr,
                "resolver": resolver_addr, "source": "ens_registry"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def eth_account(address):
    """Balance + nonce for an address via public RPC (keyless)."""
    try:
        if not ADDR.match((address or "").strip()):
            return {"status": "error", "error": "invalid 0x address"}
        address = address.strip()
        bal_hex = _rpc("eth_getBalance", [address, "latest"])
        nonce_hex = _rpc("eth_getTransactionCount", [address, "latest"])
        balance = int(bal_hex, 16) / 1e18
        nonce = int(nonce_hex, 16)
        db.audit("system", "onchain.eth_account", address,
                 f"bal={balance:.4f} txs={nonce}")
        return {"status": "ok", "address": address,
                "balance_eth": round(balance, 6),
                "tx_count": nonce,
                "explorer": f"https://etherscan.io/address/{address}",
                "note": "tx_count = on-chain activity depth (nonce)"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def nfts(address):
    """NFT holdings (OpenSea v2, key optional) + honest degradation."""
    try:
        import os
        import requests
        if not ADDR.match((address or "").strip()):
            return {"status": "error", "error": "invalid 0x address"}
        key = os.getenv("OPENSEA_API_KEY")
        if not key:
            return {"status": "unconfigured",
                    "error": "OPENSEA_API_KEY not set (free tier at opensea.io "
                             "developers)",
                    "keyless_hint": f"browse https://opensea.io/account/"
                                    f"{address} manually or via browserrender"}
        r = requests.get(
            "https://api.opensea.io/api/v2/accounts/" + address + "/nfts",
            headers={**UA, "X-API-KEY": key}, params={"limit": 50}, timeout=T)
        if r.status_code == 404:
            return {"status": "ok", "address": address, "nfts": [],
                    "note": "no NFTs indexed for this address"}
        if r.status_code != 200:
            return {"status": "error", "error": f"OpenSea HTTP {r.status_code}"}
        rows = r.json().get("nfts") or []
        out = [{
            "name": n.get("name"), "collection": (n.get("collection") or {}).get("name"),
            "identifier": n.get("identifier"),
            "contract": n.get("contract"),
            "image_url": n.get("image_url"),
        } for n in rows[:50]]
        return {"status": "ok", "address": address, "count": len(out), "nfts": out}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "nfts": []}


def anchor(query, case_id=None, queried_by="system"):
    """Resolve an ENS/address query -> account profile bundle."""
    try:
        q = (query or "").strip()
        if ADDR.match(q):
            ens_name, address = None, q
        elif "." in q and not q.startswith("http"):
            res = resolve_ens(q)
            if res.get("status") != "ok":
                return res
            ens_name, address = q, res["address"]
        else:
            return {"status": "error",
                    "error": "provide an ENS name (x.eth) or 0x address"}
        acct = eth_account(address)
        bundle = {"ens": ens_name, "address": address,
                  "account": acct.get("account") or acct,
                  "nfts": nfts(address)}
        db.audit(queried_by, "onchain.anchor", q, address)
        if case_id is not None:
            art = db.store_artifact(case_id, None, "onchain", "ens+rpc",
                                    bundle, queried_by)
            bundle["artifact"] = art
        return {"status": "ok", "bundle": bundle}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}
