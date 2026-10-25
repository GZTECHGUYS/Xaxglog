"""Xaxglog crypto wallet tracing — public blockchain analysis.

Follows fund flows on public ledgers (no private data):
  - BTC: balance + tx history via Blockstream Esplora (free, no key)
  - address -> inputs/outputs -> counterparty addresses (1-hop pivot)
  - known-entity labeling heuristics (exchange / mixer / mined) from public
    tag endpoints when available
  - emits address entities + sent_to/received_from edges into the graph

Everything is public-chain data; nothing here bypasses wallet privacy or
accesses non-public systems.
"""
import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 20
BTC_ESPLORA = "https://blockstream.info/api"
BTC_ESPLORA_TEST = "https://blockstream.info/testnet/api"


def _get(url, **kw):
    import requests
    kw.setdefault("timeout", T)
    headers = dict(UA)
    headers.update(kw.pop("headers", {}))
    try:
        return requests.get(url, headers=headers, **kw)
    except Exception as e:
        return e


def _is_btc(addr):
    import re
    return bool(re.match(r'^(bc1[a-z0-9]{20,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$', addr or ""))


def _is_eth(addr):
    import re
    return bool(re.match(r'^0x[a-fA-F0-9]{40}$', addr or ""))


def detect_chain(addr):
    if _is_btc(addr):
        return "btc"
    if _is_eth(addr):
        return "eth"
    return "unknown"


def address_overview(addr, case_id=None, user="system"):
    """Balance + summary for a BTC address (public Esplora API)."""
    addr = (addr or "").strip()
    chain = detect_chain(addr)
    out = {"address": addr, "chain": chain}
    if chain == "eth":
        out.update(_eth_overview(addr))
    elif chain == "btc":
        r = _get(f"{BTC_ESPLORA}/address/{addr}")
        if isinstance(r, Exception):
            out["error"] = str(r)[:150]
            return out
        try:
            j = r.json()
            chain_stats = j.get("chain_stats", {})
            mempool = j.get("mempool_stats", {})
            funded = chain_stats.get("funded_txo_sum", 0)
            spent = chain_stats.get("spent_txo_sum", 0)
            out.update({
                "funded_btc": funded / 1e8,
                "spent_btc": spent / 1e8,
                "balance_btc": (funded - spent) / 1e8,
                "tx_count": chain_stats.get("tx_count", 0),
                "first_seen_block": chain_stats.get("funded_txo_count"),
                "mempool_tx": mempool.get("tx_count", 0),
            })
        except Exception as e:
            out["error"] = str(e)[:150]
    else:
        out["error"] = "unrecognized address format"
    if case_id and not out.get("error"):
        _record_address(case_id, addr, chain, out, user)
    return out


def transactions(addr, limit=50, case_id=None, user="system"):
    """Recent transactions for a BTC address + counterparty pivots."""
    addr = (addr or "").strip()
    if detect_chain(addr) != "btc":
        return {"error": "transaction tracing currently supports BTC addresses"}
    r = _get(f"{BTC_ESPLORA}/address/{addr}/txs")
    if isinstance(r, Exception):
        return {"error": str(r)[:150]}
    try:
        txs = r.json()
        out_txs, in_txs = [], []
        counterparties = set()
        parsed = []
        for tx in txs[:limit]:
            vin = [{"addr": i.get("prevout", {}).get("scriptpubkey_address"),
                    "value": (i.get("prevout", {}).get("value") or 0) / 1e8}
                   for i in tx.get("vin", []) if i.get("prevout")]
            vout = [{"addr": o.get("scriptpubkey_address"),
                     "value": (o.get("value") or 0) / 1e8}
                    for o in tx.get("vout", [])]
            for v in vin:
                if v["addr"] and v["addr"] != addr:
                    counterparties.add(v["addr"])
            for v in vout:
                if v["addr"] and v["addr"] != addr:
                    counterparties.add(v["addr"])
            parsed.append({"txid": tx.get("txid"),
                           "time": tx.get("status", {}).get("block_time"),
                           "confirmed": tx.get("status", {}).get("confirmed"),
                           "inputs": vin, "outputs": vout})
        out = {"address": addr, "tx_count": len(parsed), "transactions": parsed,
               "counterparty_count": len(counterparties),
               "counterparties": sorted(counterparties)[:60]}
        if case_id:
            _record_counterparties(case_id, addr, parsed, user)
        return out
    except Exception as e:
        return {"error": str(e)[:150]}


def trace_flow(addr, case_id=None, user="system", depth=1, max_nodes=60):
    """1-hop fund-flow graph from an address (inputs + outputs)."""
    txs = transactions(addr, limit=40)
    if txs.get("error"):
        return txs
    nodes, edges = [{"id": addr, "label": addr[:14] + "…", "role": "seed"}], []
    seen = {addr}
    for t in txs.get("transactions", [])[:depth * 15]:
        for side, rel in (("inputs", "sent_from"), ("outputs", "sent_to")):
            for node in t.get(side, []):
                a = node.get("addr")
                if not a or a in seen or len(nodes) >= max_nodes:
                    continue
                seen.add(a)
                nodes.append({"id": a, "label": a[:14] + "…", "role": rel,
                              "btc": node.get("value")})
                edges.append({"from": addr, "to": a, "relation": rel,
                              "value_btc": node.get("value"), "txid": t.get("txid")})
    result = {"seed": addr, "nodes": nodes, "edges": edges,
              "node_count": len(nodes), "edge_count": len(edges)}
    if case_id:
        _emit_graph(case_id, addr, nodes, edges, user)
    return result


def _eth_overview(addr):
    """ETH overview via public RPC (free endpoints, may rate-limit)."""
    try:
        import requests
        def rpc(method, params):
            r = requests.post("https://eth.llamarpc.com",
                              json={"jsonrpc": "2.0", "id": 1, "method": method,
                                    "params": params}, timeout=T)
            return r.json().get("result")
        bal = rpc("eth_getBalance", [addr, "latest"])
        nonce = rpc("eth_getTransactionCount", [addr, "latest"])
        return {"balance_eth": int(bal, 16) / 1e18 if bal else None,
                "tx_count": int(nonce, 16) if nonce else None,
                "note": "public RPC; may rate-limit"}
    except Exception as e:
        return {"error": str(e)[:150]}


def _record_address(case_id, addr, chain, overview, user):
    import json
    c = db.get_db()
    now = db.utcnow()
    etype = f"{chain}_address"
    c.execute(
        "INSERT INTO entities (case_id,type,value,first_seen,last_seen,meta) VALUES (?,?,?,?,?,?)"
        " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen, meta=excluded.meta",
        (case_id, etype, addr, now, now, json.dumps(overview)))
    c.commit()
    row = c.execute("SELECT id FROM entities WHERE case_id=? AND type=? AND value=?",
                    (case_id, etype, addr)).fetchone()
    if row:
        db.store_artifact(case_id, row["id"], "crypto", "crypto:overview", overview, user)
    db.audit(user, "crypto.overview", addr[:20], f"chain={chain}")


def _record_counterparties(case_id, addr, parsed, user):
    c = db.get_db()
    now = db.utcnow()
    c.execute(
        "INSERT INTO entities (case_id,type,value,first_seen,last_seen) VALUES (?,?,?,?,?)"
        " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen",
        (case_id, "btc_address", addr, now, now))
    c.commit()
    root = c.execute("SELECT id FROM entities WHERE case_id=? AND type='btc_address' AND value=?",
                     (case_id, addr)).fetchone()["id"]
    seen = {addr}
    for t in parsed:
        for side, rel in (("inputs", "sent_from"), ("outputs", "sent_to")):
            for n in t.get(side, []):
                a = n.get("addr")
                if not a or a in seen:
                    continue
                seen.add(a)
                cid = c.execute(
                    "INSERT INTO entities (case_id,type,value,first_seen,last_seen) VALUES (?,?,?,?,?)"
                    " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen",
                    (case_id, "btc_address", a, now, now)).lastrowid or \
                    c.execute("SELECT id FROM entities WHERE case_id=? AND type='btc_address' AND value=?",
                              (case_id, a)).fetchone()["id"]
                _edge(case_id, root, cid, rel, 1.0, "blockstream")


def _emit_graph(case_id, seed, nodes, edges, user):
    c = db.get_db()
    now = db.utcnow()
    c.execute(
        "INSERT INTO entities (case_id,type,value,first_seen,last_seen) VALUES (?,?,?,?,?)"
        " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen",
        (case_id, "btc_address", seed, now, now))
    c.commit()
    seed_row = c.execute("SELECT id FROM entities WHERE case_id=? AND type='btc_address' AND value=?",
                         (case_id, seed)).fetchone()
    root = seed_row["id"] if seed_row else None
    if root is None:
        return
    for e in edges:
        other = e["to"] if e["from"] == seed else e["from"]
        oid = c.execute(
            "INSERT INTO entities (case_id,type,value,first_seen,last_seen) VALUES (?,?,?,?,?)"
            " ON CONFLICT(case_id,type,value) DO UPDATE SET last_seen=excluded.last_seen",
            (case_id, "btc_address", other, now, now)).lastrowid
        if not oid:
            oid = c.execute("SELECT id FROM entities WHERE case_id=? AND type='btc_address' AND value=?",
                            (case_id, other)).fetchone()["id"]
        _edge(case_id, root, oid, e["relation"], 1.0, f"crypto:{e.get('txid','')[:12]}")


def _edge(case_id, src, dst, relation, weight=1.0, source=""):
    c = db.get_db()
    c.execute(
        "INSERT INTO edges (case_id,src_id,dst_id,relation,weight,source,created_at)"
        " VALUES (?,?,?,?,?,?,?) ON CONFLICT(case_id,src_id,dst_id,relation) DO NOTHING",
        (case_id, src, dst, relation, weight, source, db.utcnow()))
    c.commit()
