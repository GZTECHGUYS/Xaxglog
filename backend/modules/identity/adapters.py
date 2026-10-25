"""Keyless public-source adapters used by the identity orchestrator.

Every function returns a list of normalized rows::

    {"source", "label", "name", "url", "match", "detail", ...}

They never raise on HTTP/network errors; callers receive an ``errors`` map so
a blocked or rate-limited source is visible instead of looking like "no hit".
Only public APIs/pages are used.  No login, captcha solving or auth bypass.
"""
from __future__ import annotations

import html as _html
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

UA = {"User-Agent": "Xaxglog-OSINT/2.0 (+public-source research)"}
T = 14

_BLOCK_MARKERS = (
    "captcha", "unusual traffic", "verifying your browser", "are you a robot",
    "just a moment", "cf-chl", "challenge-platform", "access denied",
    "request blocked", "client challenge", "enable javascript and cookies",
    "checking your browser", "login required", "please log in",
    "rate limit", "too many requests",
)


def _get(url, *, params=None, headers=None, timeout=T):
    h = dict(UA)
    if headers:
        h.update(headers)
    try:
        return requests.get(url, params=params, headers=h, timeout=timeout)
    except Exception as e:
        return e


def _post(url, *, json_body=None, headers=None, timeout=T):
    h = dict(UA)
    if headers:
        h.update(headers)
    try:
        return requests.post(url, json=json_body, headers=h, timeout=timeout)
    except Exception as e:
        return e


def _classify(r):
    if isinstance(r, Exception):
        return "error"
    if r.status_code in (401, 403, 429, 451):
        return "blocked"
    if r.status_code >= 500:
        return "error"
    head = (r.text or "")[:6000].lower()
    if any(m in head for m in _BLOCK_MARKERS):
        return "blocked"
    return "ok" if r.status_code < 400 else "error"


def _json(r):
    try:
        return r.json()
    except Exception:
        return None


def _clean(value):
    if not isinstance(value, str):
        value = " ".join(str(x) for x in value) if isinstance(value, (list, tuple)) else str(value or "")
    value = re.sub(r"<[^>]+>", " ", value or "")
    return re.sub(r"\s+", " ", _html.unescape(value)).strip()


def match_score(query, candidate):
    q = {t for t in re.split(r"[^\w]+", (query or "").lower()) if len(t) > 1}
    c = {t for t in re.split(r"[^\w]+", (candidate or "").lower()) if len(t) > 1}
    if not q:
        return 0.0
    return round(len(q & c) / len(q), 3)


def _row(source, label, name, url="", match=None, **extra):
    if isinstance(url, (list, tuple)):
        url = next((str(x) for x in url if x), "")
    rec = {
        "source": source,
        "label": label,
        "name": _clean(name),
        "url": str(url or ""),
        "match": round(float(match if match is not None else 0.0), 3),
    }
    for k, v in extra.items():
        if v not in (None, "", [], {}):
            rec[k] = v
    return rec


def _raise_for(r, source):
    st = _classify(r)
    if st != "ok":
        if st == "blocked":
            raise RuntimeError("blocked")
        if isinstance(r, Exception):
            raise RuntimeError(str(r)[:120])
        raise RuntimeError("http %s" % getattr(r, "status_code", "error"))


# ---------------------------------------------------------------- people
def gitlab(name):
    r = _get("https://gitlab.com/api/v4/users", params={"search": name, "per_page": 8})
    _raise_for(r, "gitlab")
    rows = _json(r) or []
    out = []
    for u in rows if isinstance(rows, list) else []:
        full = u.get("name") or u.get("username") or ""
        out.append(_row("gitlab_users", "GitLab users", full,
                        u.get("web_url") or "", match_score(name, full + " " + (u.get("username") or "")),
                        handle=u.get("username"), location=u.get("location"),
                        bio=u.get("bio"), platform="GitLab"))
    return sorted(out, key=lambda x: -x["match"])[:8]


def pubmed(name):
    term = '"%s"[Author]' % name
    r = _get("https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi",
             params={"db": "pubmed", "term": term, "retmode": "json", "retmax": 8})
    _raise_for(r, "pubmed")
    ids = ((_json(r) or {}).get("esearchresult") or {}).get("idlist") or []
    if not ids:
        return []
    r2 = _get("https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi",
              params={"db": "pubmed", "id": ",".join(ids), "retmode": "json"})
    _raise_for(r2, "pubmed")
    result = (_json(r2) or {}).get("result") or {}
    out = []
    for pmid in ids:
        item = result.get(pmid) or {}
        authors = [a.get("name") for a in item.get("authors") or [] if a.get("name")]
        if not any(match_score(name, a) >= 0.5 for a in authors):
            continue
        title = item.get("title") or ""
        out.append(_row("pubmed", "PubMed", name,
                        "https://pubmed.ncbi.nlm.nih.gov/%s/" % pmid,
                        match=1.0, title=_clean(title), authors=authors[:8],
                        journal=item.get("fulljournalname"), date=item.get("pubdate")))
    return out[:8]


def europepmc(name):
    r = _get("https://www.ebi.ac.uk/europepmc/webservices/rest/search",
             params={"query": 'AUTH:"%s"' % name, "format": "json", "pageSize": 8})
    _raise_for(r, "europepmc")
    rows = (((_json(r) or {}).get("resultList") or {}).get("result")) or []
    out = []
    for x in rows:
        authors = x.get("authorString") or ""
        if not any(match_score(name, a.strip()) >= 0.5 for a in authors.split(",")):
            continue
        out.append(_row("europepmc", "Europe PMC", name,
                        "https://europepmc.org/article/%s/%s" % (x.get("source") or "MED", x.get("id") or ""),
                        match=1.0, title=_clean(x.get("title")), authors=authors,
                        journal=x.get("journalTitle"), date=x.get("firstPublicationDate")))
    return out[:8]


def _oaf_value(value):
    """Unwrap OpenAIRE's ``{"$": value}`` / list-of-dicts shape."""
    if isinstance(value, list):
        return [_oaf_value(x) for x in value]
    if isinstance(value, dict):
        return value.get("$") or value.get("content") or value.get("@name")
    return value


def openaire(name):
    r = _get("https://api.openaire.eu/search/publications",
             params={"author": name, "format": "json", "size": 8})
    _raise_for(r, "openaire")
    data = _json(r) or {}
    results = (((data.get("response") or {}).get("results") or {}).get("result")) or []
    if isinstance(results, dict):
        results = [results]
    out = []
    for rec in results:
        oaf = (((rec.get("metadata") or {}).get("oaf:entity") or {}).get("oaf:result")) or {}
        title = _oaf_value(oaf.get("title")) or ""
        creators = _oaf_value(oaf.get("creator")) or []
        if isinstance(creators, str):
            creators = [creators]
        creators = [c for c in creators if isinstance(c, str)]
        if not creators:
            continue
        matched = max(creators, key=lambda c: match_score(name, c))
        score = match_score(name, matched)
        if score < 0.5:
            continue
        # Prefer a DOI or a public OpenAIRE search page; never invent a hit URL.
        url = "https://explore.openaire.eu/search/publications?keyword=" + urllib.parse.quote(name)
        pid = oaf.get("pid")
        pids = pid if isinstance(pid, list) else [pid]
        for p in pids:
            if isinstance(p, dict) and (p.get("@classid") or "").lower() == "doi":
                val = _oaf_value(p)
                if val:
                    url = "https://doi.org/" + str(val)
                    break
        out.append(_row("openaire", "OpenAIRE", matched, url, score,
                        title=_clean(title), authors=creators[:8]))
        if len(out) >= 8:
            break
    return out


def doaj(name):
    r = _get("https://doaj.org/api/search/articles/" + urllib.parse.quote(name))
    _raise_for(r, "doaj")
    rows = (_json(r) or {}).get("results") or []
    out = []
    for x in rows:
        bib = x.get("bibjson") or {}
        authors = [a.get("name") for a in bib.get("author") or [] if a.get("name")]
        if not any(match_score(name, a) >= 0.5 for a in authors):
            continue
        out.append(_row("doaj", "DOAJ", name,
                        (x.get("id") and "https://doaj.org/article/" + x.get("id")) or "",
                        match=1.0, title=_clean(bib.get("title")),
                        authors=authors[:8], journal=(bib.get("journal") or {}).get("title")))
    return out[:8]


def datacite(name):
    r = _get("https://api.datacite.org/dois",
             params={"query": name, "page[size]": 8})
    _raise_for(r, "datacite")
    rows = ((_json(r) or {}).get("data")) or []
    out = []
    for x in rows:
        attrs = x.get("attributes") or {}
        creators = [c.get("name") for c in attrs.get("creators") or [] if c.get("name")]
        if not any(match_score(name, c) >= 0.5 for c in creators):
            continue
        out.append(_row("datacite", "DataCite", name,
                        "https://doi.org/" + (attrs.get("doi") or ""),
                        match=1.0, title=_clean((attrs.get("titles") or [{}])[0].get("title")),
                        authors=creators[:8], publisher=attrs.get("publisher")))
    return out[:8]


def zenodo(name):
    r = _get("https://zenodo.org/api/records", params={"q": name, "size": 8})
    _raise_for(r, "zenodo")
    rows = (_json(r) or {}).get("hits", {}).get("hits") or []
    out = []
    for x in rows:
        meta = x.get("metadata") or {}
        creators = [c.get("name") for c in meta.get("creators") or [] if c.get("name")]
        if not any(match_score(name, c) >= 0.5 for c in creators):
            continue
        out.append(_row("zenodo", "Zenodo", name,
                        x.get("links", {}).get("self_html") or x.get("doi_url") or "",
                        match=1.0, title=_clean(meta.get("title")),
                        authors=creators[:8], doi=meta.get("doi")))
    return out[:8]


def figshare(name):
    r = _post("https://api.figshare.com/v2/articles/search",
              json_body={"search_for": name, "page_size": 8})
    _raise_for(r, "figshare")
    rows = _json(r) or []
    out = []
    for x in rows if isinstance(rows, list) else []:
        authors = [a.get("full_name") for a in x.get("authors") or [] if a.get("full_name")]
        if not any(match_score(name, a) >= 0.5 for a in authors):
            continue
        out.append(_row("figshare", "Figshare", name,
                        x.get("url_public_html") or x.get("url") or "",
                        match=1.0, title=_clean(x.get("title")),
                        authors=authors[:8], doi=x.get("doi")))
    return out[:8]


def osf(name):
    r = _get("https://api.osf.io/v2/users/",
             params={"filter[full_name]": name, "page[size]": 8})
    _raise_for(r, "osf")
    rows = (_json(r) or {}).get("data") or []
    out = []
    for x in rows:
        attrs = x.get("attributes") or {}
        full = attrs.get("full_name") or ""
        out.append(_row("osf_users", "OSF users", full,
                        (x.get("links") or {}).get("html") or "",
                        match_score(name, full), handle=attrs.get("username")))
    return sorted(out, key=lambda x: -x["match"])[:8]


def google_books(name):
    r = _get("https://www.googleapis.com/books/v1/volumes",
             params={"q": 'inauthor:"%s"' % name, "maxResults": 8})
    _raise_for(r, "google_books")
    rows = (_json(r) or {}).get("items") or []
    out = []
    for x in rows:
        info = x.get("volumeInfo") or {}
        authors = info.get("authors") or []
        if not any(match_score(name, a) >= 0.5 for a in authors):
            continue
        out.append(_row("google_books", "Google Books", name,
                        info.get("infoLink") or "", match=1.0,
                        title=_clean(info.get("title")), authors=authors[:8],
                        published=info.get("publishedDate")))
    return out[:8]


def internet_archive(name):
    q = 'creator:"%s" OR title:"%s"' % (name, name)
    r = _get("https://archive.org/advancedsearch.php",
             params={"q": q, "fl[]": ["identifier", "title", "creator", "year"],
                     "rows": 8, "output": "json"})
    _raise_for(r, "internet_archive")
    rows = (((_json(r) or {}).get("response") or {}).get("docs")) or []
    out = []
    for x in rows:
        creators = x.get("creator") or []
        if isinstance(creators, str):
            creators = [creators]
        if creators and not any(match_score(name, c) >= 0.5 for c in creators):
            continue
        out.append(_row("internet_archive", "Internet Archive", name,
                        "https://archive.org/details/" + (x.get("identifier") or ""),
                        match=1.0 if not creators else max(match_score(name, c) for c in creators),
                        title=_clean(x.get("title")), authors=creators[:8], year=x.get("year")))
    return out[:8]


def viaf(name):
    # VIAF's SRU JSON shape changes frequently; AutoSuggest is stable and
    # returns public authority records with a canonical VIAF id.
    r = _get("https://viaf.org/viaf/AutoSuggest", params={"query": name},
             headers={"Accept": "application/json"})
    _raise_for(r, "viaf")
    data = _json(r) or {}
    rows = data.get("result") or []
    out = []
    for x in rows:
        display = x.get("displayForm") or x.get("term") or ""
        vid = x.get("viafid") or x.get("recordID") or ""
        if not display or not vid:
            continue
        out.append(_row("viaf", "VIAF", display,
                        "https://viaf.org/viaf/%s" % vid,
                        match_score(name, display), nametype=x.get("nametype")))
    return sorted(out, key=lambda x: -x["match"])[:8]


def littlesis(name):
    r = _get("https://littlesis.org/api/entities/search", params={"q": name})
    _raise_for(r, "littlesis")
    rows = (_json(r) or {}).get("data") or []
    out = []
    for x in rows:
        attrs = x.get("attributes") or {}
        full = attrs.get("name") or ""
        out.append(_row("littlesis", "LittleSis", full,
                        "https://littlesis.org/entity/%s" % (x.get("id") or ""),
                        match_score(name, full), entity_type=attrs.get("type"),
                        description=_clean(attrs.get("description"))))
    return sorted(out, key=lambda x: -x["match"])[:8]


# ---------------------------------------------------------------- records
def sec_edgar(name):
    r = _get("https://efts.sec.gov/LATEST/search-index",
             params={"q": '"%s"' % name},
             headers={"User-Agent": "Xaxglog-OSINT/2.0 admin@example.com"})
    _raise_for(r, "sec_edgar")
    hits = (((_json(r) or {}).get("hits") or {}).get("hits")) or []
    out = []
    for h in hits[:8]:
        src = h.get("_source") or {}
        display = src.get("display_names") or src.get("entity_name") or name
        if isinstance(display, list):
            display = ", ".join(display[:2])
        out.append(_row("sec_edgar", "SEC EDGAR", display,
                        "https://www.sec.gov/Archives/edgar/data/%s" % (src.get("file_num") or ""),
                        match_score(name, display), form=src.get("form"),
                        filed=src.get("file_date"), description=_clean(src.get("file_description"))))
    return out


def gleif(name):
    r = _get("https://api.gleif.org/api/v1/lei-records",
             params={"filter[entity.legalName]": name, "page[size]": 8})
    _raise_for(r, "gleif")
    rows = (_json(r) or {}).get("data") or []
    out = []
    for x in rows:
        attrs = x.get("attributes") or {}
        entity = attrs.get("entity") or {}
        legal = entity.get("legalName") or {}
        full = legal.get("name") or name
        out.append(_row("gleif", "GLEIF LEI", full,
                        "https://search.gleif.org/#/record/" + (attrs.get("lei") or ""),
                        match_score(name, full), lei=attrs.get("lei"),
                        jurisdiction=entity.get("jurisdiction"),
                        status=entity.get("status")))
    return out


def courtlistener(name):
    r = _get("https://www.courtlistener.com/api/rest/v4/search/", params={"q": name})
    _raise_for(r, "courtlistener")
    rows = (_json(r) or {}).get("results") or []
    out = []
    for x in rows[:8]:
        out.append(_row("courtlistener", "CourtListener",
                        x.get("caseName") or x.get("case_name") or name,
                        "https://www.courtlistener.com" + (x.get("absolute_url") or ""),
                        match_score(name, x.get("caseName") or x.get("case_name") or ""),
                        court=x.get("court"), date=x.get("dateFiled")))
    return out


def propublica(name):
    r = _get("https://projects.propublica.org/nonprofits/api/v2/search.json",
             params={"q": name})
    _raise_for(r, "propublica")
    rows = (_json(r) or {}).get("organizations") or []
    out = []
    for x in rows[:8]:
        full = x.get("name") or ""
        out.append(_row("propublica", "ProPublica Nonprofit Explorer", full,
                        "https://projects.propublica.org/nonprofits/organizations/%s" % (x.get("ein") or ""),
                        match_score(name, full), ein=str(x.get("ein") or ""),
                        city=x.get("city"), state=x.get("state")))
    return out


def opensanctions(name):
    r = _get("https://api.opensanctions.org/search/default", params={"q": name, "limit": 8})
    _raise_for(r, "opensanctions")
    rows = (_json(r) or {}).get("results") or []
    out = []
    for x in rows[:8]:
        full = x.get("caption") or x.get("name") or ""
        out.append(_row("opensanctions", "OpenSanctions", full,
                        "https://www.opensanctions.org/entities/%s/" % (x.get("id") or ""),
                        match_score(name, full), schema=x.get("schema"),
                        datasets=x.get("datasets")))
    return out


# ---------------------------------------------------------------- code
def github_repos(name):
    r = _get("https://api.github.com/search/repositories",
             params={"q": name, "per_page": 8},
             headers={"Accept": "application/vnd.github+json"})
    _raise_for(r, "github_repos")
    rows = (_json(r) or {}).get("items") or []
    return [_row("github_repos", "GitHub repositories", x.get("full_name") or "",
                 x.get("html_url") or "", match_score(name, x.get("full_name") or ""),
                 description=_clean(x.get("description")), stars=x.get("stargazers_count"))
            for x in rows[:8]]


def gitlab_projects(name):
    r = _get("https://gitlab.com/api/v4/projects", params={"search": name, "per_page": 8})
    _raise_for(r, "gitlab_projects")
    rows = _json(r) or []
    return [_row("gitlab_projects", "GitLab projects", x.get("path_with_namespace") or "",
                 x.get("web_url") or "", match_score(name, x.get("path_with_namespace") or ""),
                 description=_clean(x.get("description")))
            for x in rows if isinstance(rows, list)]


def codeberg_repos(name):
    r = _get("https://codeberg.org/api/v1/repos/search", params={"q": name, "limit": 8})
    _raise_for(r, "codeberg_repos")
    rows = (_json(r) or {}).get("data") or []
    return [_row("codeberg_repos", "Codeberg repositories", x.get("full_name") or "",
                 x.get("html_url") or "", match_score(name, x.get("full_name") or ""),
                 description=_clean(x.get("description")))
            for x in rows[:8]]


def hn(name):
    r = _get("https://hn.algolia.com/api/v1/search", params={"query": name, "hitsPerPage": 8})
    _raise_for(r, "hn_algolia")
    rows = (_json(r) or {}).get("hits") or []
    return [_row("hn_algolia", "Hacker News", x.get("title") or x.get("story_title") or name,
                 x.get("url") or ("https://news.ycombinator.com/item?id=" + str(x.get("objectID") or "")),
                 match_score(name, (x.get("title") or "") + " " + (x.get("author") or "")),
                 author=x.get("author"), points=x.get("points"))
            for x in rows[:8]]


def devto(name):
    r = _get("https://dev.to/api/articles", params={"per_page": 8})
    _raise_for(r, "devto")
    rows = _json(r) or []
    out = []
    for x in rows if isinstance(rows, list) else []:
        title = x.get("title") or ""
        if match_score(name, title) < 0.34:
            continue
        out.append(_row("devto", "DEV Community", title, x.get("url") or "",
                        match_score(name, title), author=(x.get("user") or {}).get("name")))
    return out[:8]


def lobsters(name):
    r = _get("https://lobste.rs/search.json", params={"q": name})
    _raise_for(r, "lobsters")
    data = _json(r)
    rows = data if isinstance(data, list) else (data or {}).get("stories") or []
    return [_row("lobsters", "Lobsters", x.get("title") or name,
                 x.get("url") or x.get("comments_url") or "",
                 match_score(name, x.get("title") or ""),
                 author=x.get("submitter_user") or x.get("submitter"))
            for x in rows[:8] if isinstance(x, dict)]


def huggingface(name):
    r = _get("https://huggingface.co/api/models", params={"search": name, "limit": 8})
    _raise_for(r, "huggingface")
    rows = _json(r) or []
    return [_row("huggingface", "Hugging Face", x.get("modelId") or x.get("id") or "",
                 "https://huggingface.co/" + (x.get("modelId") or x.get("id") or ""),
                 match_score(name, x.get("modelId") or x.get("id") or ""),
                 downloads=x.get("downloads"))
            for x in rows if isinstance(rows, list)]


def npm(name):
    r = _get("https://registry.npmjs.org/-/v1/search", params={"text": name, "size": 8})
    _raise_for(r, "npm")
    rows = (_json(r) or {}).get("objects") or []
    out = []
    for x in rows[:8]:
        pkg = x.get("package") or {}
        out.append(_row("npm", "npm registry", pkg.get("name") or "",
                        pkg.get("links", {}).get("npm") or "",
                        match_score(name, pkg.get("name") or ""),
                        description=_clean(pkg.get("description"))))
    return out


def crates(name):
    r = _get("https://crates.io/api/v1/crates", params={"q": name, "per_page": 8})
    _raise_for(r, "crates")
    rows = (_json(r) or {}).get("crates") or []
    return [_row("crates", "crates.io", x.get("name") or "",
                 "https://crates.io/crates/" + (x.get("name") or ""),
                 match_score(name, x.get("name") or ""),
                 description=_clean(x.get("description")), downloads=x.get("downloads"))
            for x in rows[:8]]


def dockerhub(name):
    r = _get("https://hub.docker.com/v2/search/repositories/",
             params={"query": name, "page_size": 8})
    _raise_for(r, "dockerhub")
    rows = (_json(r) or {}).get("results") or []
    return [_row("dockerhub", "Docker Hub", x.get("repo_name") or "",
                 "https://hub.docker.com/r/" + (x.get("repo_name") or ""),
                 match_score(name, x.get("repo_name") or ""),
                 description=_clean(x.get("short_description")), stars=x.get("star_count"))
            for x in rows[:8]]


def grep_app(name):
    r = _get("https://grep.app/api/search", params={"q": name})
    _raise_for(r, "grep_app")
    data = _json(r) or {}
    rows = ((data.get("hits") or {}).get("hits")) or []
    out = []
    for x in rows[:8]:
        repo = ((x.get("repo") or {}).get("raw") or "")
        path = ((x.get("path") or {}).get("raw") or "")
        out.append(_row("grep_app", "grep.app", repo + " " + path,
                        "https://grep.app/search?q=%s" % urllib.parse.quote(name),
                        match_score(name, repo + " " + path), repo=repo, path=path))
    return out


def searchcode(name):
    r = _get("https://searchcode.com/api/codesearch_I/", params={"q": name})
    _raise_for(r, "searchcode")
    rows = (_json(r) or {}).get("results") or []
    return [_row("searchcode", "searchcode", x.get("filename") or x.get("name") or name,
                 x.get("url") or "", match_score(name, x.get("filename") or ""),
                 repo=x.get("repo"), language=x.get("language"))
            for x in rows[:8]]


# ---------------------------------------------------------------- infra
def dns(name):
    r = _get("https://dns.google/resolve", params={"name": name, "type": "A"})
    _raise_for(r, "dns_google")
    data = _json(r) or {}
    return [_row("dns_google", "Google DNS", name, "https://dns.google/",
                 match=1.0, answers=data.get("Answer") or [])]


def crtsh(name):
    r = _get("https://crt.sh/", params={"q": "%." + name, "output": "json"})
    _raise_for(r, "crtsh")
    rows = _json(r) or []
    names = sorted({e.get("name_value") for e in rows if isinstance(e, dict) and e.get("name_value")})
    return [_row("crtsh", "crt.sh", n, "https://crt.sh/?q=%25." + urllib.parse.quote(n),
                 match_score(name, n)) for n in names[:8]]


def urlscan(name):
    r = _get("https://urlscan.io/api/v1/search/", params={"q": "domain:" + name, "size": 8})
    _raise_for(r, "urlscan")
    rows = (_json(r) or {}).get("results") or []
    return [_row("urlscan", "urlscan.io", (x.get("page") or {}).get("url") or "",
                 x.get("result") or "", match_score(name, (x.get("page") or {}).get("url") or ""),
                 task=x.get("task"), verdicts=x.get("verdicts"))
            for x in rows[:8]]


def wayback(name):
    r = _get("https://web.archive.org/cdx/search/cdx",
             params={"url": name, "output": "json", "limit": 8})
    _raise_for(r, "wayback")
    rows = _json(r) or []
    out = []
    for row in rows[1:9] if isinstance(rows, list) and len(rows) > 1 else []:
        if isinstance(row, list) and len(row) >= 3:
            out.append(_row("wayback", "Wayback Machine", row[2],
                            "https://web.archive.org/web/%s/%s" % (row[1], row[2]),
                            match_score(name, row[2]), timestamp=row[1], status=row[4] if len(row) > 4 else ""))
    return out


def ipapi(name):
    r = _get("http://ip-api.com/json/" + name,
             params={"fields": "status,country,countryCode,regionName,city,isp,org,as,query"})
    _raise_for(r, "ipapi")
    data = _json(r) or {}
    return [_row("ipapi", "ip-api.com", data.get("query") or name,
                 "https://ip-api.com/#" + (data.get("query") or name), match=1.0,
                 country=data.get("country"), city=data.get("city"),
                 isp=data.get("isp"), org=data.get("org"), asn=data.get("as"))]


def rdap(name):
    r = _get("https://rdap.org/domain/" + name)
    _raise_for(r, "rdap")
    data = _json(r) or {}
    return [_row("rdap", "RDAP", name, "https://rdap.org/domain/" + name, match=1.0,
                 registrar=data.get("entities"), events=data.get("events"),
                 nameservers=data.get("nameservers"))]


def nominatim(name):
    r = _get("https://nominatim.openstreetmap.org/search",
             params={"q": name, "format": "json", "limit": 8},
             headers={"Accept": "application/json"})
    _raise_for(r, "nominatim")
    rows = _json(r) or []
    return [_row("nominatim", "OpenStreetMap", x.get("display_name") or "",
                 "https://www.openstreetmap.org/?mlat=%s&mlon=%s" % (x.get("lat"), x.get("lon")),
                 match_score(name, x.get("display_name") or ""),
                 lat=x.get("lat"), lon=x.get("lon"), place_type=x.get("type"))
            for x in rows[:8]]


def restcountries(name):
    r = _get("https://countries.dev/name/" + urllib.parse.quote(name))
    _raise_for(r, "restcountries")
    rows = _json(r) or []
    if isinstance(rows, dict):
        rows = [rows]
    return [_row("restcountries", "countries.dev", x.get("name") or "",
                 "https://countries.dev/name/" + urllib.parse.quote(name),
                 match_score(name, x.get("name") or ""),
                 capital=x.get("capital"), region=x.get("region"), population=x.get("population"))
            for x in rows if isinstance(x, dict)]


def worldbank(name):
    r = _get("https://api.worldbank.org/v2/country", params={"format": "json", "per_page": 8})
    _raise_for(r, "worldbank")
    rows = _json(r) or []
    data = rows[1] if isinstance(rows, list) and len(rows) > 1 else []
    return [_row("worldbank", "World Bank", x.get("name") or "",
                 "https://data.worldbank.org/country/" + (x.get("iso2Code") or ""),
                 match_score(name, x.get("name") or ""), iso2=x.get("iso2Code"),
                 region=(x.get("region") or {}).get("value"))
            for x in data[:8] if isinstance(x, dict)]


def commoncrawl(name):
    r = _get("https://index.commoncrawl.org/collinfo.json")
    _raise_for(r, "commoncrawl")
    rows = _json(r) or []
    return [_row("commoncrawl", "Common Crawl", x.get("name") or "",
                 x.get("cdx-api") or "", match_score(name, x.get("name") or ""))
            for x in rows[:8] if isinstance(x, dict)]


def opensky(name):
    r = _get("https://opensky-network.org/api/states/all")
    _raise_for(r, "opensky")
    data = _json(r) or {}
    return [_row("opensky", "OpenSky", name, "https://opensky-network.org/network/explorer",
                 match=1.0, time=data.get("time"), states=(data.get("states") or [])[:5])]


def bgpview(name):
    r = _get("https://api.bgpview.io/ip/" + name)
    _raise_for(r, "bgpview")
    data = _json(r) or {}
    return [_row("bgpview", "BGPView", name, "https://bgpview.io/ip/" + name, match=1.0,
                 data=data.get("data"))]


def certstream(name):
    return [_row("certstream", "Certificate Transparency", name,
                 "https://certstream.calidog.io/", match=1.0,
                 note="Stream endpoint; use the certstream module for live watches.")]


# ---------------------------------------------------------------- social
def reddit(name):
    r = _get("https://www.reddit.com/search.json", params={"q": name, "limit": 8},
             headers={"Accept": "application/json"})
    _raise_for(r, "reddit")
    rows = ((_json(r) or {}).get("data") or {}).get("children") or []
    return [_row("reddit", "Reddit", (x.get("data") or {}).get("title") or name,
                 "https://www.reddit.com" + ((x.get("data") or {}).get("permalink") or ""),
                 match_score(name, (x.get("data") or {}).get("title") or ""),
                 author=(x.get("data") or {}).get("author"))
            for x in rows[:8]]


def telegram(name):
    r = _get("https://t.me/s/" + urllib.parse.quote(name))
    _raise_for(r, "telegram")
    page = r.text or ""
    title = re.search(r"<meta[^>]+property=[\"']og:title[\"'][^>]+content=[\"']([^\"']+)", page, re.I)
    desc = re.search(r"<meta[^>]+property=[\"']og:description[\"'][^>]+content=[\"']([^\"']+)", page, re.I)
    return [_row("telegram_preview", "Telegram public preview",
                 _clean(title.group(1)) if title else name,
                 "https://t.me/s/" + urllib.parse.quote(name), match=1.0,
                 description=_clean(desc.group(1)) if desc else "")]


def weibo(name):
    r = _get("https://s.weibo.com/weibo", params={"q": name})
    _raise_for(r, "weibo")
    page = r.text or ""
    title = re.search(r"<title>(.*?)</title>", page, re.S | re.I)
    return [_row("weibo", "Weibo", _clean(title.group(1)) if title else name,
                 "https://s.weibo.com/weibo?q=" + urllib.parse.quote(name),
                 match=1.0, note="Public search page; login walls are reported as blocked.")]


def keybase(name):
    r = _get("https://keybase.io/_/api/1.0/user/lookup.json",
             params={"username": name, "fields": "basics,profile"})
    _raise_for(r, "keybase")
    data = (_json(r) or {}).get("them") or {}
    basics = data.get("basics") or {}
    profile = data.get("profile") or {}
    if not basics:
        return []
    return [_row("keybase", "Keybase", profile.get("full_name") or basics.get("username") or name,
                 "https://keybase.io/" + (basics.get("username") or name), match=1.0,
                 handle=basics.get("username"), bio=_clean(profile.get("bio")),
                 location=profile.get("location"))]


# ---------------------------------------------------------------- runner
# ---------------------------------------------------------------- extra public records / code / infra
def dbpedia(name):
    esc = (name or "").replace("\\", "\\\\").replace('"', '\\"')
    query = (
        'SELECT ?s ?label ?abstract WHERE { ?s rdfs:label "%s"@en . '
        'OPTIONAL { ?s rdfs:label ?label FILTER(lang(?label)="en") } '
        'OPTIONAL { ?s dbo:abstract ?abstract FILTER(lang(?abstract)="en") } } LIMIT 8'
    ) % esc
    r = _get("https://dbpedia.org/sparql", params={"query": query, "format": "json"},
             headers={"Accept": "application/sparql-results+json"})
    _raise_for(r, "dbpedia")
    bindings = (((_json(r) or {}).get("results") or {}).get("bindings")) or []
    out = []
    for b in bindings:
        uri = (b.get("s") or {}).get("value") or ""
        label = (b.get("label") or {}).get("value") or uri.rsplit("/", 1)[-1].replace("_", " ")
        abstract = _clean((b.get("abstract") or {}).get("value") or "")
        if uri:
            out.append(_row("dbpedia", "DBpedia", label, uri,
                            match_score(name, label), detail=abstract[:240]))
    return sorted(out, key=lambda x: -x["match"])[:8]


def brreg(name):
    r = _get("https://data.brreg.no/enhetsregisteret/api/enheter",
             params={"navn": name, "size": 8})
    _raise_for(r, "brreg")
    rows = (((_json(r) or {}).get("_embedded") or {}).get("enheter")) or []
    out = []
    for x in rows:
        org = x.get("organisasjonsnummer") or ""
        label = x.get("navn") or ""
        out.append(_row("brreg", "Brønnøysund Register Centre", label,
                        "https://data.brreg.no/enhetsregisteret/api/enheter/%s" % org,
                        match_score(name, label), org=org,
                        detail=x.get("organisasjonsform", {}).get("beskrivelse") if isinstance(x.get("organisasjonsform"), dict) else ""))
    return sorted(out, key=lambda x: -x["match"])[:8]


def recherche_entreprises(name):
    r = _get("https://recherche-entreprises.api.gouv.fr/search",
             params={"q": name, "per_page": 8})
    _raise_for(r, "recherche_entreprises")
    rows = (_json(r) or {}).get("results") or []
    out = []
    for x in rows:
        siren = x.get("siren") or ""
        label = x.get("nom_complet") or x.get("nom_raison_sociale") or ""
        out.append(_row("recherche_entreprises", "Recherche d'entreprises (FR)", label,
                        "https://annuaire-entreprises.data.gouv.fr/entreprise/%s" % siren,
                        match_score(name, label), siren=siren,
                        detail=x.get("activite_principale") or x.get("siege", {}).get("libelle_commune") if isinstance(x.get("siege"), dict) else ""))
    return sorted(out, key=lambda x: -x["match"])[:8]


def vies(vat):
    raw = re.sub(r"[\s-]+", "", (vat or "")).upper()
    if len(raw) < 4 or not raw[:2].isalpha():
        return []
    ms, number = raw[:2], raw[2:]
    r = _get("https://ec.europa.eu/taxation_customs/vies/rest-api/ms/%s/vat/%s" %
             (ms, urllib.parse.quote(number)))
    _raise_for(r, "vies")
    data = _json(r) or {}
    if not data.get("isValid"):
        return []
    label = data.get("name") or raw
    return [_row("vies", "EU VIES VAT", label,
                 "https://ec.europa.eu/taxation_customs/vies/#/vat-validation",
                 1.0, vat=raw, detail=_clean(data.get("address") or "")[:240])]


def _ckan(portal, label, name, source_id):
    r = _get(portal, params={"q": name, "rows": 8})
    _raise_for(r, source_id)
    rows = (((_json(r) or {}).get("result") or {}).get("results")) or []
    out = []
    for x in rows:
        title = x.get("title") or x.get("name") or ""
        url = x.get("url") or x.get("landing_page") or x.get("name") or ""
        if url and not str(url).startswith("http"):
            url = "https://" + url
        out.append(_row(source_id, label, title, url, match_score(name, title),
                        detail=_clean(x.get("notes") or "")[:240],
                        organization=(x.get("organization") or {}).get("title") if isinstance(x.get("organization"), dict) else ""))
    return sorted(out, key=lambda x: -x["match"])[:8]


def data_gov_uk(name):
    return _ckan("https://data.gov.uk/api/3/action/package_search",
                 "data.gov.uk", name, "data_gov_uk")


def data_gov_au(name):
    return _ckan("https://data.gov.au/data/api/3/action/package_search",
                 "data.gov.au", name, "data_gov_au")


def data_gov_ie(name):
    return _ckan("https://data.gov.ie/api/3/action/package_search",
                 "data.gov.ie", name, "data_gov_ie")


def data_europa(name):
    r = _get("https://data.europa.eu/api/hub/search/search",
             params={"q": name, "limit": 8})
    _raise_for(r, "data_europa")
    rows = (((_json(r) or {}).get("result") or {}).get("results")) or []
    out = []
    for x in rows:
        title = x.get("title") or {}
        if isinstance(title, dict):
            title = title.get("en") or next(iter(title.values()), "")
        title = _clean(title)
        url = x.get("landing_page") or x.get("resource") or ""
        out.append(_row("data_europa", "data.europa.eu", title, url,
                        match_score(name, title),
                        detail=_clean(x.get("description") or "")[:240]))
    return sorted(out, key=lambda x: -x["match"])[:8]


def federal_register(name):
    r = _get("https://www.federalregister.gov/api/v1/documents.json",
             params={"conditions[term]": name, "per_page": 8})
    _raise_for(r, "federal_register")
    rows = (_json(r) or {}).get("results") or []
    out = []
    for x in rows:
        title = x.get("title") or ""
        out.append(_row("federal_register", "US Federal Register", title,
                        x.get("html_url") or "", match_score(name, title),
                        detail=_clean(x.get("abstract") or "")[:240],
                        date=x.get("publication_date"),
                        agencies=", ".join(a.get("name") or "" for a in (x.get("agencies") or []) if isinstance(a, dict))))
    return sorted(out, key=lambda x: -x["match"])[:8]


def rubygems(name):
    r = _get("https://rubygems.org/api/v1/search.json", params={"query": name})
    _raise_for(r, "rubygems")
    rows = _json(r) or []
    out = []
    for x in rows if isinstance(rows, list) else []:
        label = x.get("name") or ""
        out.append(_row("rubygems", "RubyGems", label,
                        x.get("project_uri") or "https://rubygems.org/gems/%s" % label,
                        match_score(name, label + " " + (x.get("info") or "")),
                        detail=_clean(x.get("info") or "")[:240], version=x.get("version")))
    return sorted(out, key=lambda x: -x["match"])[:8]


def packagist(name):
    r = _get("https://packagist.org/search.json", params={"q": name})
    _raise_for(r, "packagist")
    rows = (_json(r) or {}).get("results") or []
    out = []
    for x in rows:
        label = x.get("name") or ""
        out.append(_row("packagist", "Packagist", label, x.get("url") or "",
                        match_score(name, label + " " + (x.get("description") or "")),
                        detail=_clean(x.get("description") or "")[:240]))
    return sorted(out, key=lambda x: -x["match"])[:8]


def nuget(name):
    r = _get("https://azuresearch-usnc.nuget.org/query",
             params={"q": name, "take": 8})
    _raise_for(r, "nuget")
    rows = (_json(r) or {}).get("data") or []
    out = []
    for x in rows:
        label = x.get("id") or ""
        out.append(_row("nuget", "NuGet", label,
                        x.get("projectUrl") or "https://www.nuget.org/packages/%s" % label,
                        match_score(name, label + " " + (x.get("description") or "")),
                        detail=_clean(x.get("description") or "")[:240], version=x.get("version")))
    return sorted(out, key=lambda x: -x["match"])[:8]


def maven_central(name):
    r = _get("https://search.maven.org/solrsearch/select",
             params={"q": name, "rows": 8, "wt": "json"})
    _raise_for(r, "maven")
    rows = (((_json(r) or {}).get("response") or {}).get("docs")) or []
    out = []
    for x in rows:
        g, a, v = x.get("g") or "", x.get("a") or "", x.get("latestVersion") or ""
        label = ("%s:%s" % (g, a)).strip(":")
        out.append(_row("maven", "Maven Central", label,
                        "https://search.maven.org/artifact/%s/%s/%s/jar" % (g, a, v),
                        match_score(name, label), version=v))
    return sorted(out, key=lambda x: -x["match"])[:8]


def ripe_stat(name):
    r = _get("https://stat.ripe.net/data/searchcomplete/data.json",
             params={"resource": name})
    _raise_for(r, "ripe_stat")
    cats = (((_json(r) or {}).get("data") or {}).get("categories")) or []
    out = []
    for cat in cats:
        for x in cat.get("suggestions") or []:
            label = x.get("label") or x.get("value") or ""
            out.append(_row("ripe_stat", "RIPE Stat", label,
                            "https://stat.ripe.net/%s" % urllib.parse.quote(label),
                            match_score(name, label),
                            detail=x.get("description") or ""))
    return out[:8]


def shodan_internetdb(name):
    ip = (name or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F:.]+", ip):
        return []
    r = _get("https://internetdb.shodan.io/%s" % urllib.parse.quote(ip))
    if getattr(r, "status_code", 0) == 404:
        return []
    _raise_for(r, "shodan_internetdb")
    data = _json(r) or {}
    if not data.get("ip"):
        return []
    return [_row("shodan_internetdb", "Shodan InternetDB", data.get("ip"),
                 "https://www.shodan.io/host/%s" % data.get("ip"), 1.0,
                 ports=", ".join(str(p) for p in (data.get("ports") or [])),
                 hostnames=", ".join((data.get("hostnames") or [])[:5]),
                 detail=", ".join((data.get("tags") or [])[:5]))]


PEOPLE_ADAPTERS = {
    "gitlab_users": gitlab,
    "pubmed": pubmed,
    "europepmc": europepmc,
    "openaire": openaire,
    "doaj": doaj,
    "datacite": datacite,
    "zenodo": zenodo,
    "figshare": figshare,
    "osf_users": osf,
    "google_books": google_books,
    "internet_archive": internet_archive,
    "viaf": viaf,
    "littlesis": littlesis,
    "dbpedia": dbpedia,
}

RECORD_ADAPTERS = {
    "sec_edgar": sec_edgar,
    "gleif": gleif,
    "courtlistener": courtlistener,
    "propublica": propublica,
    "opensanctions": opensanctions,
    "brreg": brreg,
    "recherche_entreprises": recherche_entreprises,
    "vies": vies,
    "data_gov_uk": data_gov_uk,
    "data_gov_au": data_gov_au,
    "data_gov_ie": data_gov_ie,
    "data_europa": data_europa,
    "federal_register": federal_register,
}

CODE_ADAPTERS = {
    "github_repos": github_repos,
    "gitlab_projects": gitlab_projects,
    "codeberg_repos": codeberg_repos,
    "hn_algolia": hn,
    "devto": devto,
    "lobsters": lobsters,
    "huggingface": huggingface,
    "npm": npm,
    "crates": crates,
    "dockerhub": dockerhub,
    "grep_app": grep_app,
    "searchcode": searchcode,
    "rubygems": rubygems,
    "packagist": packagist,
    "nuget": nuget,
    "maven": maven_central,
}

INFRA_ADAPTERS = {
    "dns_google": dns,
    "crtsh": crtsh,
    "urlscan": urlscan,
    "wayback": wayback,
    "ipapi": ipapi,
    "rdap": rdap,
    "nominatim": nominatim,
    "restcountries": restcountries,
    "worldbank": worldbank,
    "commoncrawl": commoncrawl,
    "opensky": opensky,
    "bgpview": bgpview,
    "certstream": certstream,
    "ripe_stat": ripe_stat,
    "shodan_internetdb": shodan_internetdb,
}

SOCIAL_ADAPTERS = {
    "reddit": reddit,
    "telegram_preview": telegram,
    "weibo": weibo,
    "keybase": keybase,
}


def run_adapters(query, adapters, max_workers=10, limit=8):
    """Run a map of adapter functions in parallel and normalize the outcome."""
    out = {"query": query, "sources": {}, "counts": {}, "errors": {},
           "status": "ok", "total": 0}
    if not query:
        out.update({"status": "error", "error": "empty query"})
        return out
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(adapters) or 1))) as ex:
        futs = {ex.submit(fn, query): key for key, fn in adapters.items()}
        for fut in as_completed(futs):
            key = futs[fut]
            try:
                rows = fut.result() or []
                rows = [r for r in rows if isinstance(r, dict)]
                rows.sort(key=lambda r: -float(r.get("match") or 0))
                out["sources"][key] = rows[:limit]
                out["counts"][key] = len(out["sources"][key])
            except Exception as e:
                msg = str(e)[:160]
                out["sources"][key] = []
                out["counts"][key] = 0
                out["errors"][key] = msg
    out["total"] = sum(out["counts"].values())
    if out["total"] == 0:
        out["status"] = "empty" if not out["errors"] else "error"
    elif out["errors"] and out["total"] > 0:
        out["status"] = "partial"
    elif out["errors"]:
        out["status"] = "error"
    return out
