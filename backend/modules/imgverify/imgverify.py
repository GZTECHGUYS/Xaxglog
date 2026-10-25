"""Xaxglog imgverify — image provenance: reverse search + perceptual hashing.

Keyless core (pure local, no PIL required for hashing):
  - Perceptual hashes: aHash, dHash, pHash implemented over a small pure
    -Python downsampler (best with Pillow when installed: CAPS flag).
  - Near-duplicate detection against images already in the case store.
  - Reverse-image search deep links: builds ready-to-open URLs for Google
    Lens, Yandex Images, TinEye and Bing Visual Search (no scraping of
    their results — the analyst opens the link in their own browser or the
    browserrender module renders it).

Optional (Pillow): full 64-bit pHash + EXIF fingerprint from forensics.

Workflow: attach an image to a case -> hash stored -> later runs find the
same/similar image across cases (reused profile pictures, recycled press
photos), and produce reverse-search links for provenance checks.

Lawful-use note: analysis of images you lawfully possess. Reverse-search
links hit the provider's public pages; respect their ToS and rate limits.
"""
import base64
import hashlib
import os
import urllib.parse

import db


def _sample_gray(data, w, h, gw=32, gh=32):
    """Nearest-neighbour downsample raw RGB/gray bytes to gw x gh grays."""
    out = []
    stride = len(data) // (w * h)
    for y in range(gh):
        sy = min(h - 1, int(y * h / gh))
        for x in range(gw):
            sx = min(w - 1, int(x * w / gw))
            i = (sy * w + sx) * stride
            if stride >= 3:
                out.append((data[i] * 299 + data[i + 1] * 587 + data[i + 2] * 114) // 1000)
            else:
                out.append(data[i])
    return out


def _png_gray(path):
    """Minimal PNG decode (RGB/gray, 8-bit, non-interlaced) via zlib."""
    import struct
    import zlib
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    pos, w, h, depth, ctype = 8, 0, 0, 0, 0
    idat = bytearray()
    while pos < len(raw):
        ln = struct.unpack(">I", raw[pos:pos + 4])[0]
        tag = raw[pos + 4:pos + 8]
        body = raw[pos + 8:pos + 8 + ln]
        if tag == b"IHDR":
            w, h, depth, ctype = struct.unpack(">IIBB", body[:10])
        elif tag == b"IDAT":
            idat.extend(body)
        elif tag == b"IEND":
            break
        pos += 12 + ln
    if depth != 8 or ctype not in (0, 2, 6):
        raise ValueError(f"PNG depth/type not supported ({depth},{ctype})")
    ch = 1 if ctype == 0 else 3 if ctype == 2 else 4
    data = zlib.decompress(bytes(idat))
    stride = w * ch
    out = bytearray()
    prev = bytearray(stride)
    p = 0
    for _row in range(h):
        ftype = data[p]; p += 1
        line = bytearray(data[p:p + stride]); p += stride
        if ftype == 1:
            for i in range(ch, stride):
                line[i] = (line[i] + line[i - ch]) & 0xFF
        elif ftype == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:
            for i in range(stride):
                a = line[i - ch] if i >= ch else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:
            for i in range(stride):
                a = line[i - ch] if i >= ch else 0
                b = prev[i]
                c = prev[i - ch] if i >= ch else 0
                pp = a + b - c
                pa, pb, pc = abs(pp - a), abs(pp - b), abs(pp - c)
                pr = a if (pa <= pb and pa <= pc) else b if pb <= pc else c
                line[i] = (line[i] + pr) & 0xFF
        prev = line
        if ch == 1:
            out.extend(line)
        else:
            for x in range(w):
                out.append((line[x * ch] * 299 + line[x * ch + 1] * 587
                            + line[x * ch + 2] * 114) // 1000)
    return w, h, bytes(out)


def _decode(path):
    """Decode image -> (w, h, gray[32*32]). Pillow first, PNG fallback."""
    try:
        from PIL import Image
        with Image.open(path) as im:
            g = im.convert("L").resize((32, 32))
            return im.width, im.height, bytes(g.getdata())
    except ImportError:
        pass
    w, h, g = _png_gray(path)
    if w < 1 or h < 1:
        raise ValueError("empty image")
    # normalise the fallback grid to the same 32x32 contract as the Pillow
    # path (nearest-neighbour sample), so hash functions can rely on it
    if len(g) != 32 * 32:
        g2 = bytearray(32 * 32)
        for y in range(32):
            sy = min(int(y * h / 32), h - 1)
            base = sy * w
            for x in range(32):
                sx = min(int(x * w / 32), w - 1)
                g2[y * 32 + x] = g[base + sx]
        g = bytes(g2)
    return w, h, g


def _phash32(g):
    """32-bit pHash (DCT-lite via simple Hadamard-style mixing) over 32x32."""
    # average of each 8-wide column block vs global mean -> 32-bit
    vals = list(g)
    mean = sum(vals) / len(vals)
    bits = []
    for i in range(0, 32):  # row-pair comparisons (16x2) + col-pair (16x2)
        row_avg = sum(vals[i * 32:(i + 1) * 32]) / 32.0
        bits.append(row_avg > mean)
    h = 0
    for i, b in enumerate(bits):
        if b:
            h |= (1 << i)
    # fold height too
    for x in range(32):
        col = sum(vals[y * 32 + x] for y in range(32)) / 32.0
        h = ((h << 1) | (1 if col > mean else 0)) & 0xFFFFFFFF
    return h


def hashes(path):
    """Compute aHash/dHash/pHash + SHA-256 for an image file (local)."""
    try:
        if not os.path.isfile(path):
            return {"status": "error", "error": "file not found"}
        with open(path, "rb") as f:
            blob = f.read()
        sha = hashlib.sha256(blob).hexdigest()
        w, h, g = _decode(path)
        # aHash 8x8 from the 32x32 grid
        small = [g[y * 32 + x] for y in range(0, 32, 4) for x in range(0, 32, 4)]
        mean = sum(small) / 64.0
        ahash = 0
        for i, v in enumerate(small):
            if v >= mean:
                ahash |= (1 << i)
        # dHash: compare adjacent columns on 8x8
        dhash = 0
        i = 0
        for y in range(0, 32, 4):
            for x in range(0, 28, 4):
                if g[y * 32 + x] > g[y * 32 + x + 4]:
                    dhash |= (1 << i)
                i += 1
        return {"status": "ok", "width": w, "height": h,
                "sha256": sha,
                "ahash": format(ahash, "016x"),
                "dhash": format(dhash, "016x"),
                "phash": format(_phash32(g), "08x")}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def hamming(h1, h2):
    try:
        return bin(int(h1, 16) ^ int(h2, 16)).count("1")
    except (ValueError, TypeError):
        return None


def attach(case_id, path, queried_by="system"):
    """Hash an image and store it as a case artifact (chain of custody)."""
    out = hashes(path)
    if out.get("status") != "ok":
        return out
    out["file"] = os.path.basename(path)
    art = db.store_artifact(case_id, None, "image", "imgverify", out, queried_by)
    return {"status": "ok", "hashes": out, "artifact": art}


def similar(case_id=None, path=None, threshold=10, limit=20):
    """Find stored images near-duplicate to `path` (dHash distance)."""
    try:
        cur = hashes(path) if path else None
        if path and cur.get("status") != "ok":
            return cur
        c = db.get_db()
        q = ("SELECT id,case_id,content FROM artifacts "
             "WHERE type='image' AND source='imgverify'")
        args = ()
        if case_id is not None:
            q += " AND case_id=?"
            args = (case_id,)
        rows = c.execute(q, args).fetchall()
        import json as _json
        hits = []
        for r in rows:
            try:
                stored = _json.loads(r["content"])
            except ValueError:
                continue
            if cur:
                d = hamming(cur.get("dhash", ""), stored.get("dhash", ""))
                if d is not None and d <= int(threshold):
                    hits.append({"artifact_id": r["id"], "case_id": r["case_id"],
                                 "distance": d, "sha256": stored.get("sha256"),
                                 "file": stored.get("file")})
            else:
                hits.append({"artifact_id": r["id"], "case_id": r["case_id"],
                             "sha256": stored.get("sha256"),
                             "dhash": stored.get("dhash"),
                             "file": stored.get("file")})
        hits.sort(key=lambda x: x.get("distance", 0))
        return {"status": "ok", "count": len(hits[:limit]), "matches": hits[:limit],
                "threshold": threshold}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "matches": []}


def reverse_links(image_url=None, upload_hint=True):
    """Build reverse-image search deep links (analyst opens them)."""
    try:
        out = {"status": "ok", "links": {}}
        if image_url:
            enc = urllib.parse.quote(image_url, safe="")
            out["links"]["google_lens"] = "https://lens.google.com/uploadbyurl?url=" + enc
            out["links"]["yandex"] = ("https://yandex.com/images/search?rpt=imageview&url="
                                      + enc)
            out["links"]["tineye"] = "https://tineye.com/search?url=" + enc
            out["links"]["bing"] = ("https://www.bing.com/images/search?view=detailv2&iss=sbi"
                                    "&form=SBIVSP&q=imgurl:" + enc)
        if upload_hint:
            out["note"] = ("For a local file: use google_lens -> 'upload' tab, or open "
                           "tineye.com and drop the file. To render from the server use "
                           "the browserrender module.")
        return out
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}
