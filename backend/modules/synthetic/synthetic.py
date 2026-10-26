"""Xaxglog synthetic-media — media authenticity triage (heuristics, local).

Analyses an image you possess for signs of manipulation/reuse and returns a
structured triage report — findings are *signals to check*, never a verdict:

  - provenance: SHA-256, hash family (ties into imgverify near-dup matching)
  - EXIF fingerprint: camera make/model, software tags (editing apps write
    "Software"), timestamps; uses forensics file_tools when its EXIF reader
    is loaded (CAPS), else a minimal JPEG-EXIF reader built in.
  - consistency checks: capture-time vs file mtime, GPS present but claims
    studio shoot, multiple software tags (capture app + editor), no camera
    signature on a "photo", PNG re-encode (no EXIF on a supposed photo).
  - prior-art: search the case store for near-identical hashes (recycled
    image used under a new caption).

Pillow optional (better EXIF); pure-JPEG fallback otherwise.

Lawful-use note: local analysis of evidence you lawfully hold. Do not treat
the score as proof — it prioritizes what a forensic examiner should review.
"""
import datetime
import json
import os
import re
import struct

import db


def _exif_jpeg(path):
    """Minimal JPEG EXIF reader: Make/Model/Software/DateTime/GPS presence."""
    tags = {}
    with open(path, "rb") as f:
        data = f.read(262144)  # first 256KB covers APP1/EXIF
    if data[:2] != b"\xff\xd8":
        return tags
    pos = 2
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            break
        marker = data[pos + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        seglen = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        if marker == 0xE1 and data[pos + 4:pos + 10] == b"Exif\x00\x00":
            tags.update(_parse_tiff(data[pos + 10:pos + 2 + seglen]))
            break
        pos += 2 + seglen
    return tags


_IFD_TAGS = {0x010F: "Make", 0x0110: "Model", 0x0131: "Software",
             0x0132: "DateTime", 0x8298: "Copyright", 0x013B: "Artist",
             0x8825: "GPS", 0x9003: "DateTimeOriginal"}


def _parse_tiff(buf):
    out = {}
    try:
        if len(buf) < 8:
            return out
        endian = "<" if buf[:2] == b"II" else ">"
        ifd = struct.unpack(endian + "I", buf[4:8])[0]
        if ifd + 2 > len(buf):
            return out
        n = struct.unpack(endian + "H", buf[ifd:ifd + 2])[0]
        for i in range(n):
            e = ifd + 2 + i * 12
            if e + 12 > len(buf):
                break
            tag, typ, cnt = struct.unpack(endian + "HHI", buf[e:e + 8])
            name = _IFD_TAGS.get(tag)
            if not name:
                continue
            if typ == 2:  # ASCII
                off = struct.unpack(endian + "I", buf[e + 8:e + 12])[0]
                s = buf[off:off + cnt].split(b"\x00")[0].decode("ascii", "replace")
                out[name] = s
            elif typ == 3:
                v = struct.unpack(endian + "H", buf[e + 8:e + 10])[0]
                out[name] = v
            elif tag == 0x8825:
                out["GPS"] = True
    except Exception:
        pass
    return out


def _pil_exif(path):
    try:
        from PIL import Image
        with Image.open(path) as im:
            ex = im.getexif()
            out = {}
            for tid, name in ((271, "Make"), (272, "Model"), (305, "Software"),
                              (306, "DateTime"), (33432, "Copyright")):
                v = ex.get(tid)
                if v:
                    out[name] = str(v)
            if ex.get(34853):
                out["GPS"] = True
            return out
    except Exception:
        return {}


EDITORS = ("photoshop", "lightroom", "gimp", "capture one", "snapseed",
           "pixlr", "canva", "affinity", "dxcam", "preview", "paint.net",
           "imagemagick", "ffmpeg", "sangaku", "dall-e", "midjourney",
           "stable diffusion", "stablediffusion", "generative")


def assess(path, case_id=None, queried_by="system"):
    """Triage one image; returns signals list + follow-up recommendations."""
    try:
        if not os.path.isfile(path):
            return {"status": "error", "error": "file not found"}
        import db as _db  # noqa: F811 — explicit for readers
        with open(path, "rb") as f:
            blob = f.read()
        sha = __import__("hashlib").sha256(blob).hexdigest()
        ext = os.path.splitext(path)[1].lower()
        tags = _exif_jpeg(path) if ext in (".jpg", ".jpeg") else _pil_exif(path)
        if not tags:
            tags = _pil_exif(path)

        signals, recs = [], []
        software = (tags.get("Software") or "").strip()
        soft_l = software.lower()
        editors_hit = [e for e in EDITORS if e in soft_l]
        if editors_hit:
            signals.append(f"editing/creation software tag present: {software!r}")
            recs.append("Confirm the edit chain: is an edited copy expected?")
        gen_hit = [e for e in ("dall-e", "midjourney", "stable diffusion", "comfyui")
                   if e in soft_l]
        if gen_hit:
            signals.append(f"generative-tool marker in software tag ({software!r})")
            recs.append("Treat as synthetic until provenance from originator is verified.")
        if ext in (".jpg", ".jpeg") and not tags.get("Make") and not tags.get("Model"):
            signals.append("JPEG photo without camera Make/Model EXIF")
            recs.append("Screenshot, edited export or stripped EXIF — check prior-art hash.")
        if ext == ".png":
            signals.append("PNG container (typically re-encode/export; screenshots are PNG)")
        if tags.get("GPS"):
            signals.append("GPS coordinates embedded in EXIF")
            recs.append("Compare GPS against the claimed scene location.")
        else:
            if tags.get("Make"):
                signals.append("camera EXIF present but GPS absent")
        # timestamp consistency
        dt_raw = tags.get("DateTimeOriginal") or tags.get("DateTime")
        mtime = datetime.datetime.fromtimestamp(os.path.getmtime(path))
        if dt_raw:
            try:
                dt = datetime.datetime.strptime(dt_raw[:19], "%Y:%m:%d %H:%M:%S")
                delta = abs((mtime - dt).total_seconds())
                if delta > 86400 * 30:
                    signals.append(
                        f"EXIF capture time differs from file mtime by {delta / 86400:.0f} days")
                    recs.append("Big capture/mtime gap — likely copied or batch-processed.")
            except ValueError:
                pass

        # prior-art: near-identical images already in custody
        prior = []
        try:
            import modules.imgverify.imgverify as IV
            h = IV.hashes(path)
            if h.get("status") == "ok":
                c = db.get_db()
                for r in c.execute(
                        "SELECT id,case_id,content FROM artifacts WHERE type='image' "
                        "AND source='imgverify'").fetchall():
                    try:
                        st = json.loads(r["content"])
                    except ValueError:
                        continue
                    if st.get("sha256") == sha:
                        continue  # same file
                    d = IV.hamming(h.get("dhash", ""), st.get("dhash", ""))
                    if d is not None and d <= 8:
                        prior.append({"artifact_id": r["id"], "case_id": r["case_id"],
                                      "distance": d, "file": st.get("file"),
                                      "sha256": st.get("sha256")})
                if case_id is not None:
                    db.store_artifact(case_id, None, "image", "imgverify", h, queried_by)
        except Exception:
            pass
        if prior:
            signals.append(f"{len(prior)} near-identical image(s) already in the case store")
            recs.append("Recycled image — check the new caption/claim against prior use.")

        score = min(100, len(signals) * 18 + (40 if gen_hit else 0)
                    + (15 if editors_hit else 0))
        report = {
            "file": os.path.basename(path), "sha256": sha,
            "exif": tags or None, "signals": signals,
            "recommendations": recs or ["No red flags from metadata alone — "
                                        "provenance check recommended."],
            "prior_art": prior,
            "triage_score": score,
            "verdict_hint": ("review" if score >= 40 else "low-signal"),
        }
        db.audit(queried_by, "synthetic.assess", path, f"score={score} signals={len(signals)}")
        if case_id is not None:
            art = db.store_artifact(case_id, None, "synthetic", "synthetic-media",
                                    report, queried_by)
            report["artifact"] = art
        return {"status": "ok", "report": report}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}
