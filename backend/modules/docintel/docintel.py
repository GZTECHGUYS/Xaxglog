"""Xaxglog docintel — document metadata & hidden-content extraction.

Keyless, fully local (stdlib only, optional libs improve coverage):
  - PDF: /Info dictionary (Author, Title, Creator, Producer, CreationDate,
    ModDate), XMP packet, embedded URI harvest, page/object counts,
    JavaScript/launch-action presence (PDF red flags), stream entropy hint.
  - DOCX/XLSX/PPTX: zip + core.xml (creator, lastModifiedBy, revision,
    created/modified), app.xml (application, company), hyperlink targets,
    hidden-slide/worksheet markers.
  - Legacy DOC: summary-information stream strings (best-effort).
  - Image docs: delegates to synthetic-media EXIF triage when applicable.

Output: authorship/timeline/producer facts + red-flag signals, stored as a
custody artifact. Complements forensics/file_tools (EXIF) and doc-level
search inside cases.

Lawful-use note: parses documents in your lawful possession. Extracts what
the file itself discloses — nothing is executed (JS/launch actions are
*reported*, never run).
"""
import datetime
import os
import re
import zipfile

import db

DOC_EXTS = (".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".odt")


def _pdf_info(path):
    import re as _re
    with open(path, "rb") as f:
        blob = f.read(4_000_000)  # metadata lives near start; cap read
    out = {"meta": {}, "signals": [], "urls": [], "objects": {}}
    m = _re.search(rb"/Info\s+(\d+)\s+\d+\s+R", blob)
    info = {}
    # direct /Info dict form
    for key in (b"Title", b"Author", b"Subject", b"Keywords", b"Creator",
                b"Producer", b"CreationDate", b"ModDate"):
        mm = _re.search(rb"/" + key + rb"\s*\((.*?)\)", blob, _re.S)
        if mm:
            info[key.decode()] = mm.group(1).decode("latin-1", "replace")[:300]
    # XMP packet
    xm = _re.search(rb"<x:xmpmeta[^>]*>(.*?)</x:xmpmeta>", blob, _re.S)
    xmp = {}
    if xm:
        packet = xm.group(1)
        for tag in (b"dc:creator", b"xmp:CreatorTool", b"pdf:Producer",
                    b"xmp:CreateDate", b"xmp:ModifyDate"):
            t = _re.search(rb"<" + tag + rb"[^>]*>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</",
                           packet, _re.S)
            if t:
                xmp[tag.decode()] = t.group(1).decode("utf-8", "replace")[:300]
    out["meta"] = {**info, **{"xmp:" + k: v for k, v in xmp.items()}}
    if m:
        out["objects"]["info_ref"] = int(m.group(1))
    out["urls"] = sorted({u.decode("latin-1", "replace")[:300]
                          for u in _re.findall(rb"/URI\s*\((.*?)\)", blob)})[:40]
    out["objects"]["pages"] = len(_re.findall(rb"/Type\s*/Page[^s]", blob))
    out["objects"]["obj_count"] = len(_re.findall(rb"\d+\s+\d+\s+obj", blob))
    js = _re.findall(rb"/(JavaScript|JS|Launch|EmbeddedFile|RichMedia)\b", blob)
    if js:
        out["signals"].append(
            "active content present: " +
            ", ".join(sorted({j.decode() for j in js})) + " (reported, not executed)")
    if b"/Encrypt" in blob:
        out["signals"].append("document is encrypted")
    meta = out["meta"]
    if meta.get("Creator") and meta.get("Producer") and meta["Creator"] != meta["Producer"]:
        out["signals"].append(
            f"creator {meta['Creator']!r} vs producer {meta['Producer']!r} "
            "(authoring app != final export)")
    if _re.search(rb"/CreationDate\s*\(D:(\d{14})", blob):
        out["objects"]["created"] = _re.search(
            rb"/CreationDate\s*\(D:(\d{14})", blob).group(1).decode()
    if _re.search(rb"/ModDate\s*\(D:(\d{14})", blob):
        out["objects"]["modified"] = _re.search(
            rb"/ModDate\s*\(D:(\d{14})", blob).group(1).decode()
    return out


def _ooxml(path):
    out = {"meta": {}, "signals": [], "urls": [], "objects": {}}
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())
        if "docProps/core.xml" in names:
            x = z.read("docProps/core.xml").decode("utf-8", "replace")
            for tag in ("dc:creator", "cp:lastModifiedBy", "cp:revision",
                        "dcterms:created", "dcterms:modified", "dc:title",
                        "dc:subject", "cp:keywords", "cp:category"):
                m = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", x, re.S)
                if m:
                    out["meta"][tag] = m.group(1).strip()[:300]
        if "docProps/app.xml" in names:
            x = z.read("docProps/app.xml").decode("utf-8", "replace")
            for tag in ("Application", "Company", "Manager", "TotalTime",
                        "Pages", "Words", "Slides", "HiddenSlides"):
                m = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", x, re.S)
                if m:
                    out["objects"][tag.lower()] = m.group(1).strip()[:200]
        # hyperlink targets across relationship files
        for n in names:
            if n.endswith(".rels"):
                x = z.read(n).decode("utf-8", "replace")
                for u in re.findall(r'Target="(https?://[^"]+)"', x):
                    out["urls"].append(u[:300])
        out["urls"] = sorted(set(out["urls"]))[:60]
        if "docProps/app.xml" in names and "HiddenSlides" in names:
            app = z.read("docProps/app.xml").decode("utf-8", "replace")
            m = re.search(r"<HiddenSlides>(\d+)</HiddenSlides>", app)
            if m and int(m.group(1)) > 0:
                out["signals"].append(f"{m.group(1)} hidden slide(s)")
        if any("vbaProject" in n for n in names):
            out["signals"].append("macros present (vbaProject.bin) — reported, not executed")
    app = out["objects"].get("application", "")
    meta = out["meta"]
    if meta.get("cp:lastModifiedBy") and meta.get("dc:creator") and \
            meta["cp:lastModifiedBy"] != meta["dc:creator"]:
        out["signals"].append(
            f"author {meta['dc:creator']!r} != last modifier {meta['cp:lastModifiedBy']!r}")
    if app and "word" in app.lower() or "excel" in app.lower() or "powerpnt" in app.lower():
        out["signals"].append(f"produced by {app!r}")
    return out


def _legacy_doc(path):
    """Best-effort strings from a legacy DOC SummaryInformation."""
    out = {"meta": {}, "signals": ["legacy binary DOC — best-effort parse"],
           "urls": [], "objects": {}}
    with open(path, "rb") as f:
        blob = f.read(2_000_000)
    ascii_strings = [s.decode() for s in re.findall(rb"[ -~]{6,120}", blob[:60000])]
    for s in ascii_strings:
        low = s.lower()
        if any(k in low for k in ("microsoft word", "normal.dot", "windows")):
            out["meta"].setdefault("hints", []).append(s)
        if s.startswith("http"):
            out["urls"].append(s)
    out["urls"] = sorted(set(out["urls"]))[:30]
    return out


def analyze(path, case_id=None, queried_by="system"):
    """Extract metadata + signals from a document; store as custody artifact."""
    try:
        if not os.path.isfile(path):
            return {"status": "error", "error": "file not found"}
        ext = os.path.splitext(path)[1].lower()
        if ext not in DOC_EXTS:
            return {"status": "error", "error": f"unsupported extension {ext!r}",
                    "supported": list(DOC_EXTS)}
        if ext == ".pdf":
            report = _pdf_info(path)
        elif ext in (".docx", ".xlsx", ".pptx", ".odt"):
            report = _ooxml(path)
        elif ext == ".doc":
            report = _legacy_doc(path)
        else:
            return {"status": "error", "error": "unsupported"}
        import hashlib
        with open(path, "rb") as f:
            report["sha256"] = hashlib.sha256(f.read()).hexdigest()
        report["file"] = os.path.basename(path)
        report["size"] = os.path.getsize(path)
        meta = report["meta"]
        # timeline consistency
        created, modified = meta.get("CreationDate") or meta.get("dcterms:created"), \
            meta.get("ModDate") or meta.get("dcterms:modified")
        if created and modified and str(created)[:19] != str(modified)[:19]:
            report["signals"].append(
                f"created {str(created)[:19]} but last modified {str(modified)[:19]}")
        db.audit(queried_by, "docintel.analyze", path,
                 f"signals={len(report['signals'])}")
        if case_id is not None:
            art = db.store_artifact(case_id, None, "document", "docintel",
                                    report, queried_by)
            report["artifact"] = art
        return {"status": "ok", "report": report}
    except zipfile.BadZipFile:
        return {"status": "error", "error": "not a valid OOXML zip (corrupt or legacy)"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def summarize(report):
    """Compact human-facing summary of an analyze() report."""
    meta = report.get("meta", {})
    facts = [f"{k}={v}" for k, v in meta.items()
             if k in ("Author", "dc:creator", "Creator", "Producer",
                      "xmp:CreatorTool", "cp:lastModifiedBy",
                      "dcterms:created", "CreationDate")]
    return {"file": report.get("file"),
            "facts": facts,
            "signals": report.get("signals", []),
            "urls": (report.get("urls") or [])[:10]}
