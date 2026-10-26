"""Xaxglog langintel — multilingual pivots: translation + name cross-scripts.

Keyless core:
  - MyMemory translation API (api.mymemory.translated.net) — free,
    no key (daily quota ~5k chars for anonymous), en<->100+ languages.
  - Local script machinery: script detection, diacritic stripping,
    NFC/NFD normalization, Cyrillic/Greek/Latin transliteration maps,
    Arabic/Hebrew stubs, confusable folding (extends namevar with
    *search-term* expansion rather than person-name variants).

Use: an analyst hits a Baidu/Yandex/Weibo result (regional module) or a
Russian/Ukrainian/Arabic post — translate the snippet, normalize the
person/brand name into the case's Latin index, and re-query other engines
with the transliteration.

Lawful-use note: translation of publicly available text. MyMemory stores
queries — do not submit sensitive case material verbatim; the module sends
only the snippet (<=500 chars per call).
"""
import re
import unicodedata

import db

UA = {"User-Agent": "Xaxglog-OSINT/2.0"}
T = 20
MYMEMORY = "https://api.mymemory.translated.net/get"
MAX_CHARS = 480

SCRIPTS = [
    ("Cyrillic", re.compile(r"[\u0400-\u04FF]")),
    ("Greek", re.compile(r"[\u0370-\u03FF]")),
    ("Arabic", re.compile(r"[\u0600-\u06FF\u0750-\u077F]")),
    ("Hebrew", re.compile(r"[\u0590-\u05FF]")),
    ("Han", re.compile(r"[\u4E00-\u9FFF]")),
    ("Hiragana/Katakana", re.compile(r"[\u3040-\u30FF]")),
    ("Hangul", re.compile(r"[\uAC00-\uD7AF\u1100-\u11FF]")),
    ("Thai", re.compile(r"[\u0E00-\u0E7F]")),
    ("Devanagari", re.compile(r"[\u0900-\u097F]")),
    ("Latin", re.compile(r"[A-Za-z\u00C0-\u024F]")),
]

_TRANS = {
    **{chr(c): ch for c, ch in zip(range(0x0430, 0x044F + 1),
                                    "абвгдеёжзийклмнопрстуфхцчшщъыьэюя")},
    **{chr(c): ch.upper() for c, ch in zip(range(0x0410, 0x042F + 1),
                                           "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ")},
    **dict(zip("αβγδεζηθικλμνξοπρστυφχψω",
               "abgdeziythiklmnxoprstufchpsw")),
}
DIGRAPH = {"щ": "shch", "ъ": "", "ь": "", "ё": "yo", "х": "kh",
           "ц": "ts", "ч": "ch", "ш": "sh", "ж": "zh", "э": "e", "ю": "yu", "я": "ya"}


def detect_script(text):
    found = []
    for name, rx in SCRIPTS:
        n = len(rx.findall(text or ""))
        if n:
            found.append({"script": name, "chars": n})
    found.sort(key=lambda x: -x["chars"])
    return {"status": "ok", "scripts": found,
            "dominant": found[0]["script"] if found else "unknown"}


def translate(text, source="auto", target="en"):
    """Snippet translation via MyMemory (keyless, <=480 chars/call)."""
    try:
        text = (text or "").strip()
        if not text:
            return {"status": "error", "error": "empty text"}
        if len(text) > MAX_CHARS:
            text = text[:MAX_CHARS]
            truncated = True
        else:
            truncated = False
        import requests
        # MyMemory rejects ISO codes for the source when autodetecting;
        # it accepts the literal "Autodetect" on that side of the pair.
        src = "Autodetect" if (source or "auto").lower() == "auto" else source
        langpair = f"{src}|{target}"
        r = requests.get(MYMEMORY, headers=UA,
                         params={"q": text, "langpair": langpair}, timeout=T)
        if r.status_code != 200:
            return {"status": "error", "error": f"HTTP {r.status_code}"}
        j = r.json()
        if j.get("responseStatus") not in (200, None):
            return {"status": "error",
                    "error": str(j.get("responseDetails"))[:150]}
        translated = (j.get("responseData") or {}).get("translatedText", "")
        detected = (j.get("responseData") or {}).get("detectedLanguage")
        if detected is not None:
            detected = str(detected)[:20]
        elif j.get("quotaReached"):
            detected = "quota reached"
        db.audit("system", "langintel.translate", text[:60],
                 f"{source}->{target}")
        return {"status": "ok", "source": text[:MAX_CHARS],
                "translated": translated, "detected": detected,
                "truncated": truncated, "engine": "mymemory"}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def transliterate(text):
    """Cyrillic/Greek -> Latin search terms (best-effort, keeps both forms)."""
    try:
        out = []
        for ch in unicodedata.normalize("NFC", text or ""):
            low = ch.lower()
            if low in DIGRAPH:
                out.append(DIGRAPH[low])
            elif low in _TRANS:
                out.append(_TRANS[low])
            else:
                out.append(ch)
        latin = "".join(out)
        stripped = "".join(c for c in unicodedata.normalize("NFD", latin)
                           if unicodedata.category(c) != "Mn")
        return {"status": "ok", "original": text, "translit": latin,
                "ascii_fold": stripped,
                "variants": sorted({latin, stripped, stripped.lower(),
                                    latin.replace(" ", "")})}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


def normalize(text):
    """Canonical form for cross-engine name matching."""
    t = unicodedata.normalize("NFKC", text or "").strip().lower()
    t = re.sub(r"\s+", " ", t)
    t = "".join(c for c in unicodedata.normalize("NFD", t)
                if unicodedata.category(c) != "Mn")
    t = t.replace("\u2019", "'").replace("\u2013", "-")
    conf = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
            "х": "x", "у": "y", "і": "i", "ѕ": "s"}
    folded = "".join(conf.get(c, c) for c in t)
    return {"status": "ok", "normalized": t, "confusable_fold": folded,
            "ascii": re.sub(r"[^a-z0-9@\.\-_ ]", "", folded).strip()}


def expand_terms(name, max_variants=20):
    """Full expansion pipeline: normalize + translit + confusable folds
    -> a list of search terms an analyst can feed to searchx/regional."""
    seen = []
    base = normalize(name)
    seen.append(base["normalized"])
    seen.append(base["confusable_fold"])
    tr = transliterate(name)
    if tr.get("status") == "ok":
        seen.extend(tr["variants"])
    # small case/separator matrix
    for v in list(seen):
        seen.append(v.replace(" ", ""))
        if " " in v:
            seen.append(v.replace(" ", "."))
            seen.append(v.replace(" ", "_"))
            seen.append(v.replace(" ", "-"))
    out = []
    for v in seen:
        v = v.strip()
        if v and v not in out:
            out.append(v)
        if len(out) >= max_variants:
            break
    return {"status": "ok", "original": name, "terms": out}
