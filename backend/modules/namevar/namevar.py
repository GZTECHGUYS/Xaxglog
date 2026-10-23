"""Xaxglog namevar — international name variants & homograph detection.

Purpose
-------
A subject rarely spells their name one way. This module is the transliteration
/ variant engine: it detects the script of a name, produces Latin
transliterations (Cyrillic, Arabic, Greek), folds diacritics, expands common
nicknames, strips Russian patronymics, generates leet/separator variants and
builds lookalike (homograph) domains for typosquat monitoring.

Sources
-------
No network at all — pure Unicode (unicodedata), embedded transliteration
tables and a small confusables map derived from public IDN/Homograph
literature (RFC 3490/4971-style confusable characters).

Lawful use
----------
Defensive / investigative name matching and brand-typosquat detection only.
The homograph helpers exist to *detect* lookalike domains, not to impersonate
anyone; respect third-party trademarks and never use generated lookalikes to
phouflage, phish or otherwise deceive. No credentials, no scraping.
"""
import re
import unicodedata

# ------------------------------------------------------------------ scripts
_SCRIPT_RANGES = (
    ("cyrillic", ((0x0400, 0x052F),)),
    ("latin", ((0x0041, 0x005A), (0x0061, 0x007A), (0x00C0, 0x024F))),
    ("greek", ((0x0370, 0x03FF), (0x1F00, 0x1FFF))),
    ("arabic", ((0x0600, 0x06FF), (0x0750, 0x077F), (0x08A0, 0x08FF),
                (0xFB50, 0xFDFF), (0xFE70, 0xFEFF))),
    ("han", ((0x4E00, 0x9FFF), (0x3400, 0x4DBF), (0xF900, 0xFAFF))),
    ("kana", ((0x3040, 0x30FF), (0x31F0, 0x31FF), (0xFF66, 0xFF9F))),
    ("hangul", ((0x1100, 0x11FF), (0xAC00, 0xD7AF), (0x3130, 0x318F))),
    ("hebrew", ((0x0590, 0x05FF),)),
    ("devanagari", ((0x0900, 0x097F),)),
)


def _script_of(ch):
    o = ord(ch)
    if ch.isdigit() and ch.isascii():
        return "digit"
    for name, ranges in _SCRIPT_RANGES:
        for lo, hi in ranges:
            if lo <= o <= hi:
                return name
    return None


def script_detect(s):
    """Return 'cyrillic|latin|greek|arabic|han|kana|digit|mixed|...'.

    Digits/punctuation are not scripts: "abc123" -> "latin"; two or more
    alphabetic scripts -> "mixed"; no letters at all -> "digit"/"unknown".
    """
    try:
        found = set()
        has_digit = False
        for ch in (s or ""):
            sc = _script_of(ch)
            if sc == "digit":
                has_digit = True
            elif sc:
                found.add(sc)
        if not found:
            return "digit" if has_digit else "unknown"
        if len(found) > 1:
            return "mixed"
        return next(iter(found))
    except Exception:
        return "unknown"


# ------------------------------------------------------------------ tables
_RU_TABLE = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "yo",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "shch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
    # Ukrainian / Belarusian / Bulgarian extras
    "і": "i", "ї": "yi", "є": "ye", "ґ": "g", "ў": "u", "ʼ": "", "'": "",
}

_AR_TABLE = {
    "ا": "a", "أ": "a", "ٱ": "a", "إ": "i", "آ": "a",
    "ب": "b", "ت": "t", "ث": "th", "ج": "j", "ح": "h", "خ": "kh",
    "د": "d", "ذ": "dh", "ر": "r", "ز": "z", "س": "s", "ش": "sh",
    "ص": "s", "ض": "d", "ط": "t", "ظ": "zh", "ع": "a", "غ": "gh",
    "ف": "f", "ق": "q", "ك": "k", "ل": "l", "م": "m", "ن": "n",
    "ه": "h", "ة": "a", "و": "w", "ى": "a", "ي": "y", "ی": "y",
    "ء": "", "ؤ": "u", "ئ": "i", "ﻻ": "la", "ـ": "",
}

_GR_TABLE = {
    "α": "a", "β": "b", "γ": "g", "δ": "d", "ε": "e", "ζ": "z", "η": "e",
    "θ": "th", "ι": "i", "κ": "k", "λ": "l", "μ": "m", "ν": "n", "ξ": "x",
    "ο": "o", "π": "p", "ρ": "r", "σ": "s", "ς": "s", "τ": "t", "υ": "u",
    "φ": "f", "χ": "ch", "ψ": "ps", "ω": "o",
    "ά": "a", "έ": "e", "ή": "e", "ί": "i", "ό": "o", "ύ": "u", "ώ": "o",
    "ϊ": "i", "ϋ": "u", "ΐ": "i", "ΰ": "u",
}


def _table_translit(s, table, strip_marks=True):
    """Char-by-char transliteration; upper-case maps capitalize the mapping."""
    out = []
    for ch in s or "":
        if unicodedata.combining(ch):
            continue                       # drop stray combining marks
        low = ch.lower()
        if low in table:
            m = table[low]
            if ch.isupper() and m:
                m = m[0].upper() + m[1:]
            out.append(m)
        elif strip_marks and ch.isalpha():
            folded = _fold_diacritics(ch)
            if folded != ch:
                out.append(_table_translit(folded, table, strip_marks=False))
                continue
            out.append(ch)
        else:
            out.append(ch)
    return "".join(out)


def _ru_translit(s):
    """Full Cyrillic -> Latin (Russian/Ukrainian/Bulgarian/Belarusian)."""
    return _table_translit(s, _RU_TABLE)


def _ar_translit(s):
    """Basic Arabic -> Latin (harakat removed, hamzas folded)."""
    try:
        s = re.sub("[ً-ْٰـ]", "", s or "")
        return _table_translit(s, _AR_TABLE)
    except Exception:
        return s


def _greek_translit(s):
    """Full Greek -> Latin."""
    return _table_translit(s, _GR_TABLE)


# ------------------------------------------------------------------ folding
_CUSTOM_FOLD = {
    "ß": "ss", "ẞ": "SS", "æ": "ae", "Æ": "AE", "œ": "oe", "Œ": "OE",
    "ı": "i", "İ": "I", "ø": "o", "Ø": "O", "đ": "d", "Đ": "D",
    "ł": "l", "Ł": "L", "þ": "th", "Þ": "Th", "ð": "d", "Ð": "D",
    "ĸ": "k", "ŉ": "n",
}


def _fold_diacritics(s):
    """NFKD + strip combining marks: ñ->n, é->e, ı->i (plus ligatures)."""
    try:
        s = s or ""
        for k, v in _CUSTOM_FOLD.items():
            if k in s:
                s = s.replace(k, v)
        s = unicodedata.normalize("NFKD", s)
        return "".join(c for c in s if not unicodedata.combining(c))
    except Exception:
        return s or ""


# ------------------------------------------------------------------ leet/seps
_LEET = {
    "0": ["o"], "1": ["i", "l"], "o": ["0"], "i": ["1"], "l": ["1"],
    "a": ["4", "@"], "4": ["a", "@"], "e": ["3"], "3": ["e"],
    "s": ["5", "$"], "5": ["s"], "@": ["a"], "$": ["s"],
}


def _leet_variants(s, cap=24):
    """Single-position leet substitutions, capped (0<->o, 1<->i/l, 4<->a...)."""
    out, seen = [], set()

    def push(v):
        if v not in seen:
            seen.add(v)
            out.append(v)

    push(s)
    for i, ch in enumerate(s):
        if len(out) >= cap:
            break
        for alt in _LEET.get(ch.lower(), []):
            if len(out) >= cap:
                break
            if ch.isupper() and alt.isalpha():
                alt = alt.upper()
            push(s[:i] + alt + s[i + 1:])
    return out[:cap]


def _sep_variants(s):
    """Join tokens with '', '.', '_', '-' plus spacing/case reformats."""
    try:
        toks = [t for t in re.split(r"[\s_\-.]+", s or "") if t]
        if len(toks) < 2:
            return [s] if s else []
        out = []
        for sep in ("", ".", "_", "-"):
            out.append(sep.join(toks))
            out.append(sep.join(t.lower() for t in toks))
            out.append(sep.join(t[:1].upper() + t[1:].lower() for t in toks))
        out.append(" ".join(toks))
        out.append(" ".join(t.lower() for t in toks))
        dedup, seen = [], set()
        for v in out:
            if v and v not in seen:
                seen.add(v)
                dedup.append(v)
        return dedup
    except Exception:
        return [s] if s else []


# ------------------------------------------------------------------ nicknames
_NICK_GROUPS = [
    ["robert", "bob", "rob", "bobby", "bert"],
    ["william", "will", "bill", "billy", "willie"],
    ["michael", "mike", "mick", "mickey"],
    ["john", "jack", "johnny", "jon"],
    ["james", "jim", "jimmy"],
    ["richard", "dick", "rick", "rich", "richie"],
    ["joseph", "joe", "joey"],
    ["thomas", "tom", "tommy"],
    ["charles", "charlie", "chuck"],
    ["christopher", "chris", "kit"],
    ["daniel", "dan", "danny"],
    ["matthew", "matt", "matty"],
    ["edward", "ed", "eddie", "ted", "teddy"],
    ["nicholas", "nick", "nicky"],
    ["alexander", "alex", "sasha"],
    ["alexandra", "sasha", "sandy", "alex"],
    ["stephen", "steve", "steven"],
    ["gregory", "greg"],
    ["patrick", "pat", "paddy"],
    ["donald", "don", "donnie"],
    ["ronald", "ron", "ronnie"],
    ["nathan", "nate"],
    ["timothy", "tim", "timmy"],
    ["andrew", "andy", "drew"],
    ["joshua", "josh"],
    ["benjamin", "ben", "benny"],
    ["samuel", "sam", "sammy"],
    ["anthony", "tony"],
    ["francis", "frank"],
    ["henry", "harry", "hank"],
    ["arthur", "art", "artie"],
    ["walter", "walt"],
    ["phillip", "phil", "philip"],
    ["eugene", "gene"],
    ["russell", "russ"],
    ["katherine", "kate", "katie", "kathy", "kitty"],
    ["catherine", "kate", "katie", "kathy", "cathy"],
    ["elizabeth", "liz", "beth", "betty", "betsy", "libby"],
    ["margaret", "maggie", "meg", "peggy", "marge"],
    ["jennifer", "jen", "jenny"],
    ["jessica", "jess", "jessie"],
    ["susan", "sue", "susie", "suzy"],
    ["patricia", "patty", "trish", "tricia"],
    ["deborah", "deb", "debbie", "debra"],
    ["rebecca", "becca", "becky"],
    ["cynthia", "cindy"],
    ["victoria", "vicky", "tori"],
    ["eleanor", "ellie", "nora"],
    ["dorothy", "dot", "dottie", "dolly"],
    ["virginia", "ginny"],
    ["helen", "nell", "nelly"],
    ["christina", "chris", "tina"],
    ["josephine", "jo", "josie"],
    # Russian diminutives
    ["vladimir", "vova", "volodya", "vlad"],
    ["mikhail", "misha"],
    ["dmitry", "dima", "dmitriy"],
    ["elena", "lena", "alena"],
    ["nikolai", "kolya", "nikolay"],
    ["pavel", "pasha"],
    ["yuri", "yura"],
    ["sergei", "seryozha", "sergey"],
    ["evgeny", "zhenya"],
    ["grigori", "grisha"],
    ["boris", "borya"],
    ["andrei", "andrya"],
    ["olga", "olya"],
    ["tatiana", "tanya"],
    ["natalia", "natasha", "nadya"],
    ["galina", "galya"],
    ["svetlana", "sveta"],
]

_NICK_TO_CANON = {}
_CANON_TO_NICK = {}
for _grp in _NICK_GROUPS:
    for _n in _grp:
        _NICK_TO_CANON.setdefault(_n, set()).update(_grp)
        _CANON_TO_NICK.setdefault(_grp[0], set()).update(_grp)
# nicknames shared across groups (e.g. sasha, chris) also expose their peers
for _n, _peers in list(_NICK_TO_CANON.items()):
    for _p in _peers:
        _NICK_TO_CANON.setdefault(_p, set()).update(_peers)


def _nick_candidates(token):
    """All plausible forms of one token (canonical <-> nicknames, both ways)."""
    key = re.sub(r"[^a-z]", "", (token or "").lower())
    if not key:
        return []
    out = set()
    out |= _NICK_TO_CANON.get(key, set())
    out |= _CANON_TO_NICK.get(key, set())
    out.discard(key)
    return sorted(out)


# ------------------------------------------------------------------ patronymic
_RU_PATRON = ("ovich", "evich", "ich", "ovna", "evna", "na")


def _patronymic_fold(name):
    """Drop Russian patronymic suffixes from non-first tokens.

    "Ivan Ivanovich" -> "Ivan Ivan", "Petr Petrovich Sidorov" -> ...
    Short suffixes ('na') require a >=5 char token to limit false positives.
    """
    try:
        toks = (name or "").split()
        if len(toks) < 2:
            return name
        changed = False
        for i in range(1, len(toks)):
            low = toks[i].lower()
            for suf in _RU_PATRON:
                if low.endswith(suf) and len(low) - len(suf) >= 3:
                    if suf == "na" and len(low) < 5:
                        continue
                    if len(low) - len(suf) == 0:
                        continue
                    stem = toks[i][:len(toks[i]) - len(suf)]
                    if toks[i][:1].isupper():
                        stem = stem[:1].upper() + stem[1:]
                    toks[i] = stem
                    changed = True
                    break
        return " ".join(toks) if changed else name
    except Exception:
        return name


# ------------------------------------------------------------------ variants
def variants(name, max_variants=250, leet=False):
    """Generate de-duplicated spelling variants of a personal/user name.

    Combines: original, case forms, diacritic fold, per-script translits,
    nickname expansions, first/middle swap, patronymic fold, separator
    variants and (optionally) leet. Order = priority order; cap is honored.
    """
    try:
        name = (name or "").strip()
        if not name:
            return []
        max_variants = max(1, int(max_variants or 250))
        out, seen = [], set()

        def add(v):
            v = (v or "").strip()
            if v and v not in seen and len(out) < max_variants:
                seen.add(v)
                out.append(v)

        add(name)
        add(name.lower())
        add(name.upper())
        add(name.title())

        folded = _fold_diacritics(name)
        add(folded)
        add(folded.lower())
        add(folded.title())
        if folded != name:
            add(folded.replace(" ", ""))

        # transliterate every non-latin script present
        scripts = {sc for sc in (_script_of(c) for c in name) if sc}
        for sc, fn in (("cyrillic", _ru_translit), ("arabic", _ar_translit),
                       ("greek", _greek_translit)):
            if sc in scripts:
                t = fn(name)
                add(t)
                add(t.lower())
                add(t.title())
                add(_fold_diacritics(t).lower())
                if " " in t:
                    add("".join(t.split()))

        toks = re.split(r"\s+", name)

        # nickname expansions of the first token (and each token, cap cheap)
        for idx in (0, 1):
            if idx >= len(toks):
                break
            for cand in _nick_candidates(toks[idx]):
                if idx == 0:
                    exp = " ".join([cand] + toks[1:])
                else:
                    exp = " ".join(toks[:1] + [cand] + toks[2:])
                add(exp)
                add(exp.lower())
                add(exp.title())

        # first/middle swap permutations when >=2 tokens
        if len(toks) >= 2:
            swapped = " ".join([toks[1], toks[0]] + toks[2:])
            add(swapped)
            add(swapped.lower())
            add(swapped.title())
            for cand in _nick_candidates(toks[1])[:4]:
                sw2 = " ".join([cand, toks[0]] + toks[2:])
                add(sw2)
                add(sw2.lower())

        # patronymic fold
        pf = _patronymic_fold(name)
        add(pf)
        add(pf.lower())
        add(pf.title())
        if pf != name and " " in pf:
            for cand in _nick_candidates(pf.split()[0])[:4]:
                add(" ".join([cand] + pf.split()[1:]))

        # separator variants
        for base in (name, folded, pf):
            for v in _sep_variants(base):
                add(v)

        # leet: only when digits are already present or caller opts in
        if leet or any(c.isdigit() for c in name):
            for v in _leet_variants(name, cap=24):
                add(v)
                add(v.lower())

        return out[:max_variants]
    except Exception:
        return []


def cross_script_search_terms(name, max_terms=10):
    """High-value search fan-out subset (~10 terms) for cross-script lookup."""
    try:
        name = (name or "").strip()
        if not name:
            return []
        max_terms = max(1, int(max_terms or 10))
        out, seen = [], set()

        def add(v):
            v = (v or "").strip()
            if v and v not in seen and len(out) < max_terms:
                seen.add(v)
                out.append(v)

        add(name)
        add(name.lower())
        folded = _fold_diacritics(name)
        add(folded.lower())

        scripts = {sc for sc in (_script_of(c) for c in name) if sc}
        for sc, fn in (("cyrillic", _ru_translit), ("arabic", _ar_translit),
                       ("greek", _greek_translit)):
            if sc in scripts:
                t = fn(name)
                add(t)
                add(t.lower())
                add(_fold_diacritics(t).lower())

        toks = re.split(r"\s+", name)
        if len(toks) >= 2:
            add(" ".join([toks[1], toks[0]]))
            for cand in _nick_candidates(toks[0])[:3]:
                add(" ".join([cand] + toks[1:]))
            add("".join(toks).lower())
        else:
            for cand in _nick_candidates(toks[0])[:3]:
                add(cand)
        add(_patronymic_fold(name).lower())
        return out[:max_terms]
    except Exception:
        return []


# ------------------------------------------------------------------ homographs
# ASCII char -> lookalike substitutes (cyrillic a/e/o/p/c/x/i/s/d/y,
# greek o/a/e, digits 0/1, en-dash for hyphen).
_HOMO_SWAPS = {
    "a": ["а", "α"], "A": ["А", "Α"],
    "e": ["е", "ε"], "E": ["Е", "Ε"],
    "o": ["о", "ο", "0"], "O": ["О", "Ο"],
    "p": ["р"], "P": ["Р"],
    "c": ["с"], "C": ["С"],
    "x": ["х"], "X": ["Х"],
    "i": ["і", "1"], "I": ["І"],
    "s": ["ѕ"], "S": ["Ѕ"],
    "d": ["ԁ"], "D": ["Ԁ"],
    "y": ["у"], "Y": ["У"],
    "l": ["1"], "L": ["1"],
    "-": ["–"],           # en dash
}

# lookalike char -> what it visually impersonates (for detect_confusables)
_LOOKALIKE_BACK = {}
for _a, _alts in _HOMO_SWAPS.items():
    for _alt in _alts:
        if not _alt.isascii() or _alt in ("0", "1", "–"):
            _LOOKALIKE_BACK[_alt] = _a
_LOOKALIKE_BACK.update({
    "о": "o", "О": "O", "а": "a", "А": "A", "е": "e", "Е": "E",
    "с": "c", "С": "C", "р": "p", "Р": "P", "х": "x", "Х": "X",
    "і": "i", "І": "I", "ѕ": "s", "Ѕ": "S", "ԁ": "d", "Д": "D",
    "у": "y", "У": "Y", "ο": "o", "Ο": "O", "α": "a", "Α": "A",
    "ε": "e", "Ε": "E", "–": "-",
})


def _split_domain(domain):
    d = (domain or "").strip()
    d = re.sub(r"^[a-zA-Z][\w+.-]*://", "", d)          # strip scheme
    d = d.split("/")[0].split("?")[0].split("#")[0]
    d = d.split("@")[-1]
    d = d.split(":")[0]                                  # strip port
    return d.strip(".")


def domain_homographs(domain, cap=50):
    """Lookalike domains via per-label single-char swaps (confusables).

    Returns a list of strings: the Unicode homographs first, followed by their
    punycode (IDNA) encodings, capped at `cap` total. The TLD (last label) is
    left ASCII so candidates stay syntactically plausible. Defensive use:
    register/monitor them, don't abuse them.
    """
    try:
        d = _split_domain(domain)
        if not d or "." not in d or not d.isascii() and " " in d:
            return []
        labels = d.split(".")
        if len(labels) < 2:
            return []
        tld = labels[-1]
        body = labels[:-1]
        homographs = []
        seen = set()

        def push(dom):
            if dom not in seen and len(homographs) < cap:
                seen.add(dom)
                homographs.append(dom)
                return True
            return False

        # strategy 1: swap every occurrence of one char class across the body
        # (e.g. both o's -> Cyrillic: "gооgle.com")
        for ch in sorted(set("".join(body))):
            for alt in _HOMO_SWAPS.get(ch, []):
                newbody = [lab.replace(ch, alt) for lab in body]
                if any(nb != ob for nb, ob in zip(newbody, body)):
                    push(".".join(newbody) + "." + tld)
                if len(homographs) >= cap:
                    break
            if len(homographs) >= cap:
                break

        # strategy 2: finer single-position swaps per label
        for li, lab in enumerate(body):
            for i, ch in enumerate(lab):
                for alt in _HOMO_SWAPS.get(ch, []):
                    newlab = lab[:i] + alt + lab[i + 1:]
                    push(".".join(body[:li] + [newlab] + body[li + 1:]) + "." + tld)
                    if len(homographs) >= cap:
                        break
                if len(homographs) >= cap:
                    break
            if len(homographs) >= cap:
                break
        out = list(homographs)
        for h in homographs:
            if len(out) >= cap:
                break
            try:
                pc = h.encode("idna").decode("ascii")
            except Exception:
                pc = None
            if pc and pc != h and pc not in seen:
                seen.add(pc)
                out.append(pc)
        return out[:cap]
    except Exception:
        return []


def detect_confusables(s):
    """Flag suspicious characters: [{char, codepoint, looks_like}, ...].

    Catches Cyrillic/Greek lookalikes and fullwidth forms hiding inside an
    otherwise innocent-looking string (classic homograph phishing).
    """
    try:
        out = []
        for ch in s or "":
            looks = None
            if ch in _LOOKALIKE_BACK:
                looks = _LOOKALIKE_BACK[ch]
            elif 0xFF01 <= ord(ch) <= 0xFF5E:            # fullwidth ASCII
                looks = chr(ord(ch) - 0xFEE0)
            if looks and looks != ch:
                out.append({"char": ch, "codepoint": "U+%04X" % ord(ch),
                            "looks_like": looks})
        return out
    except Exception:
        return []
