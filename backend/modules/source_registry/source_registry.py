"""Xaxglog source registry — one catalog for every public source.

The registry is deliberately data-first: every engine, people index, public
record, academic index, code index, social platform and infrastructure lookup
gets a stable id plus explicit metadata.  Modules can then ask for a *plan*
instead of hard-coding a list of sites in each search path.

Access modes
------------
``api``          free/keyless JSON or XML API
``public_html``  public HTML page/result page (scraper or link-out)
``api_or_html``  API first, HTML fallback
``optional_key`` official API that only works with an operator key
``link_out``     reliable public search/profile page; analyst opens it
``blocked``      known anti-bot/login wall (kept visible, never counted as a hit)

Statuses are intentionally separate from access mode.  A source can be
``adapter`` (code exists), ``verified`` (live-checked from this host),
``optional_key``, ``link_out`` or ``blocked``.  No blocked source is ever
silently treated as "no results".
"""
from __future__ import annotations

import re
import urllib.parse

CATEGORY_LABELS = {
    "web": "Global web search",
    "regional": "Regional web/news",
    "people": "People & identity indexes",
    "records": "Public records, company & court",
    "academic": "Academic & archives",
    "code": "Code & developer indexes",
    "social": "Social & fediverse",
    "image": "Image, video & media",
    "infrastructure": "Geospatial & infrastructure",
    "monitoring": "Monitoring & feeds",
}

ACCESS_MODES = ("api", "public_html", "api_or_html", "optional_key", "link_out", "blocked")

# Sources we have live-checked from the development host.  Keep this explicit:
# adding an adapter is not the same as proving the source is reachable.
VERIFIED_IDS = {
    # people / academic / archive
    "wikipedia", "wikidata", "openalex_authors", "crossref", "arxiv",
    "pubmed", "europepmc", "doaj", "datacite", "zenodo",
    "osf_users", "internet_archive", "github_users", "codeberg_users",
    "stackexchange", "bluesky", "mastodon", "lemmy", "hn_algolia",
    "npm", "crates", "dockerhub", "huggingface", "gleif",
    "propublica", "usaspending", "ted", "sec_edgar", "littlesis",
    "openlibrary", "orcid", "openaire", "semanticscholar_authors", "viaf",
    "dbpedia", "telegram_preview", "weibo", "keybase",
    # code / repositories / package indexes
    "github_repos", "gitlab_projects", "codeberg_repos",
    "rubygems", "packagist", "nuget", "maven",
    # records / courts / company + open-data registries
    "courtlistener", "brreg", "recherche_entreprises", "vies",
    "data_gov_uk", "data_gov_au", "data_gov_ie", "data_europa",
    "federal_register",
    # global / regional public search pages (live-checked)
    "ddg", "marginalia", "mwmbl", "wiby", "metager", "sogou",
    "so360", "naver", "daum", "yahoo_jp", "seznam",
    # infrastructure / archives
    "commoncrawl", "dns_google", "ipapi", "opensky", "rdap",
    "urlscan", "wayback", "worldbank", "certstream", "nominatim",
    "restcountries", "gdelt", "gdelt_news", "wayback_watch",
    "urlscan_watch", "telegram_watch", "certstream_watch",
    "ripe_stat", "shodan_internetdb",
}

# Sources that returned 401/403/429/captcha from the development host during
# the live verification pass.  They remain in the catalog with an adapter, but
# are not counted as verified until a later probe succeeds.
HOST_BLOCKED_IDS = {
    "gitlab_users", "google_books", "grep_app", "reddit", "opensanctions",
    "searx", "mojeek", "qwant", "yep", "ecosia", "yandex", "rambler",
    "crtsh", "lda", "lobsters",
}

# Adapters that returned a hard endpoint error (404/400/connection) from the
# development host.  Keep them visible as dead/error sources, never as hits.
HOST_ERROR_IDS = {
    "searchcode", "goo_jp", "bgpview",
}


REGISTRY: dict[str, dict] = {}
_BY_CATEGORY: dict[str, list[str]] = {}
_BY_ACCESS: dict[str, list[str]] = {}
_BY_STATUS: dict[str, list[str]] = {}


def _slug(value: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", (value or "").lower()).strip("_")
    return s or "source"


def _add(source_id, label, category, access, *, region="global", language="en",
         types=("name",), url="", search="", adapter=None, status=None,
         requires_key=False, key_env="", note="", homepage="", tags=None,
         profile_url="", domains=None):
    source_id = _slug(source_id)
    if source_id in REGISTRY:
        return REGISTRY[source_id]
    if source_id in HOST_BLOCKED_IDS:
        status = "blocked"
    elif source_id in HOST_ERROR_IDS:
        status = "error"
    elif status is None:
        if access == "optional_key":
            status = "optional_key"
        elif access == "blocked":
            status = "blocked"
        elif access == "link_out":
            status = "link_out"
        elif adapter:
            status = "adapter"
        else:
            status = "cataloged"
    if source_id in VERIFIED_IDS and status == "adapter":
        status = "verified"
    rec = {
        "id": source_id,
        "label": label,
        "category": category,
        "category_label": CATEGORY_LABELS.get(category, category),
        "region": region or "global",
        "language": language or "en",
        "types": sorted(set(types or ("name",))),
        "access": access,
        "status": status,
        "verified": status == "verified",
        "adapter": adapter or "",
        "requires_key": bool(requires_key or access == "optional_key"),
        "key_env": key_env or "",
        "url": url or search or profile_url or "",
        "search": search or "",
        "profile_url": profile_url or "",
        "homepage": homepage or url or search or "",
        "domains": sorted(set(domains or [])),
        "tags": sorted(set(tags or [])),
        "note": note,
    }
    REGISTRY[source_id] = rec
    _BY_CATEGORY.setdefault(category, []).append(source_id)
    _BY_ACCESS.setdefault(access, []).append(source_id)
    _BY_STATUS.setdefault(status, []).append(source_id)
    return rec


def _many(rows):
    for row in rows:
        _add(*row[:4], **row[4])


# ---------------------------------------------------------------- core catalog
def _build_core():
    # Global / metasearch ------------------------------------------------
    _many([
        ("ddg", "DuckDuckGo HTML", "web", "public_html",
         dict(url="https://html.duckduckgo.com/html/", search="https://duckduckgo.com/?q={q}",
              adapter="searchx.ddg", types=("name", "handle", "web"),
              note="HTML endpoint; anti-bot walls are reported as blocked.")),
        ("searx", "SearXNG public instances", "web", "api",
         dict(url="https://searx.be/search", search="https://searx.be/search?q={q}",
              adapter="searchx.searx", types=("name", "handle", "web"),
              note="Public JSON instances; first healthy instance wins.")),
        ("mojeek", "Mojeek", "web", "public_html",
         dict(url="https://www.mojeek.com/search", search="https://www.mojeek.com/search?q={q}",
              adapter="searchx.mojeek", types=("name", "handle", "web"))),
        ("wikipedia", "Wikipedia", "web", "api",
         dict(url="https://en.wikipedia.org/w/api.php", search="https://en.wikipedia.org/w/index.php?search={q}",
              adapter="searchx.wikipedia", types=("name", "web", "academic"))),
        ("wikidata", "Wikidata", "people", "api",
         dict(url="https://www.wikidata.org/w/api.php", search="https://www.wikidata.org/w/index.php?search={q}",
              adapter="people.wikidata", types=("name", "person", "identity"))),
        ("marginalia", "Marginalia Search", "web", "public_html",
         dict(url="https://search.marginalia.nu/search", search="https://search.marginalia.nu/search?query={q}",
              adapter="searchx.marginalia", types=("name", "web"),
              note="Independent small-web index; HTML parser.")),
        ("stract", "Stract", "web", "public_html",
         dict(url="https://stract.com/search", search="https://stract.com/search?q={q}",
              adapter="searchx.stract", types=("name", "web"))),
        ("mwmbl", "Mwmbl", "web", "api",
         dict(url="https://api.mwmbl.org/search", search="https://mwmbl.org/?q={q}",
              adapter="searchx.mwmbl", types=("name", "web"))),
        ("wiby", "Wiby", "web", "public_html",
         dict(url="https://wiby.me/", search="https://wiby.me/?q={q}",
              adapter="searchx.wiby", types=("name", "web"))),
        ("metager", "MetaGer", "web", "public_html",
         dict(url="https://metager.org/meta/meta.ger3", search="https://metager.org/meta/meta.ger3?eingabe={q}",
              adapter="searchx.metager", types=("name", "web"))),
        ("qwant", "Qwant", "web", "public_html",
         dict(url="https://www.qwant.com/", search="https://www.qwant.com/?q={q}",
              adapter="searchx.qwant", types=("name", "web"))),
        ("yep", "Yep", "web", "public_html",
         dict(url="https://yep.com/", search="https://yep.com/web?q={q}",
              adapter="searchx.yep", types=("name", "web"))),
        ("ecosia", "Ecosia", "web", "public_html",
         dict(url="https://www.ecosia.org/search", search="https://www.ecosia.org/search?q={q}",
              adapter="searchx.ecosia", types=("name", "web"))),
        ("startpage", "Startpage", "web", "public_html",
         dict(url="https://www.startpage.com/sp/search", search="https://www.startpage.com/sp/search?query={q}",
              adapter="searchx.startpage", types=("name", "web"),
              note="Often anti-bot walled; kept as explicit link-out/fallback.")),
        ("brave_search", "Brave Search", "web", "link_out",
         dict(search="https://search.brave.com/search?q={q}", types=("name", "web"),
              note="Official API requires a key; web UI is link-out only.")),
        ("google_cse", "Google Programmable Search", "web", "optional_key",
         dict(search="https://programmablesearchengine.google.com/", types=("name", "web"),
              requires_key=True, key_env="GOOGLE_CSE_KEY",
              note="Official API only; no result-page scraping.")),
        ("bing_api", "Bing Web Search API", "web", "optional_key",
         dict(search="https://www.bing.com/search?q={q}", types=("name", "web"),
              requires_key=True, key_env="BING_SEARCH_KEY",
              note="Official API only; no result-page scraping.")),
        ("yandex", "Yandex", "web", "public_html",
         dict(search="https://yandex.com/search/?text={q}", adapter="searchx.yandex",
              types=("name", "web"), note="Captcha-prone; reported as blocked when walled.")),
        ("baidu", "Baidu", "regional", "public_html",
         dict(search="https://www.baidu.com/s?wd={q}", adapter="searchx.baidu",
              types=("name", "web"), region="CN", language="zh")),
        ("sogou", "Sogou", "regional", "public_html",
         dict(search="https://www.sogou.com/web?query={q}", adapter="searchx.sogou",
              types=("name", "web"), region="CN", language="zh")),
        ("so360", "360 Search", "regional", "public_html",
         dict(search="https://www.so.com/s?q={q}", adapter="searchx.so360",
              types=("name", "web"), region="CN", language="zh")),
        ("shenma", "Shenma", "regional", "link_out",
         dict(search="https://m.sm.cn/s?q={q}", types=("name", "web"),
              region="CN", language="zh")),
        ("toutiao_search", "Toutiao Search", "regional", "link_out",
         dict(search="https://so.toutiao.com/search?keyword={q}", types=("name", "web"),
              region="CN", language="zh")),
        ("naver", "Naver", "regional", "public_html",
         dict(search="https://search.naver.com/search.naver?query={q}", adapter="searchx.naver",
              types=("name", "web"), region="KR", language="ko")),
        ("daum", "Daum", "regional", "public_html",
         dict(search="https://search.daum.net/search?q={q}", adapter="searchx.daum",
              types=("name", "web"), region="KR", language="ko")),
        ("yahoo_jp", "Yahoo! Japan", "regional", "public_html",
         dict(search="https://search.yahoo.co.jp/search?p={q}", adapter="searchx.yahoo_jp",
              types=("name", "web"), region="JP", language="ja")),
        ("goo_jp", "goo.ne.jp", "regional", "public_html",
         dict(search="https://search.goo.ne.jp/web.jsp?MT={q}", adapter="searchx.goo_jp",
              types=("name", "web"), region="JP", language="ja")),
        ("seznam", "Seznam", "regional", "public_html",
         dict(search="https://search.seznam.cz/?q={q}", adapter="searchx.seznam",
              types=("name", "web"), region="CZ", language="cs")),
        ("centrum", "Centrum.cz", "regional", "link_out",
         dict(search="https://search.centrum.cz/?q={q}", types=("name", "web"),
              region="CZ", language="cs")),
        ("atlas", "Atlas.cz", "regional", "link_out",
         dict(search="https://search.atlas.cz/?q={q}", types=("name", "web"),
              region="CZ", language="cs")),
        ("wp", "Wirtualna Polska", "regional", "link_out",
         dict(search="https://szukaj.wp.pl/szukaj.html?q={q}", types=("name", "web"),
              region="PL", language="pl")),
        ("onet", "Onet", "regional", "link_out",
         dict(search="https://szukaj.onet.pl/?q={q}", types=("name", "web"),
              region="PL", language="pl")),
        ("interia", "Interia", "regional", "link_out",
         dict(search="https://www.interia.pl/szukaj?q={q}", types=("name", "web"),
              region="PL", language="pl")),
        ("uol", "UOL Busca", "regional", "public_html",
         dict(search="https://busca.uol.com.br/result?q={q}", adapter="searchx.uol",
              types=("name", "web"), region="BR", language="pt")),
        ("terra", "Terra Busca", "regional", "link_out",
         dict(search="https://search.terra.com.br/search?q={q}", types=("name", "web"),
              region="BR", language="pt")),
        ("rambler", "Rambler", "regional", "public_html",
         dict(search="https://nova.rambler.ru/search?query={q}", adapter="searchx.rambler",
              types=("name", "web"), region="RU", language="ru")),
        ("mailru", "Mail.ru Search", "regional", "public_html",
         dict(search="https://go.mail.ru/search?q={q}", adapter="searchx.mailru",
              types=("name", "web"), region="RU", language="ru")),
        ("ukrnet", "Ukr.net", "regional", "link_out",
         dict(search="https://search.ukr.net/?q={q}", types=("name", "web"),
              region="UA", language="uk")),
        ("bigmir", "Bigmir", "regional", "link_out",
         dict(search="https://search.bigmir.net/?q={q}", types=("name", "web"),
              region="UA", language="uk")),
        ("coccoc", "Cốc Cốc", "regional", "link_out",
         dict(search="https://coccoc.com/search?query={q}", types=("name", "web"),
              region="VN", language="vi")),
        ("sanook", "Sanook Search", "regional", "link_out",
         dict(search="https://search.sanook.com/?q={q}", types=("name", "web"),
              region="TH", language="th")),
        ("detik", "Detik Search", "regional", "link_out",
         dict(search="https://www.detik.com/search/searchall?query={q}", types=("name", "web"),
              region="ID", language="id")),
        ("kompas", "Kompas Search", "regional", "link_out",
         dict(search="https://www.kompas.com/search/?q={q}", types=("name", "web"),
              region="ID", language="id")),
        ("rappler", "Rappler Search", "regional", "link_out",
         dict(search="https://www.rappler.com/?s={q}", types=("name", "web"),
              region="PH", language="en")),
        ("nairaland", "Nairaland Search", "regional", "link_out",
         dict(search="https://www.nairaland.com/search?q={q}", types=("name", "web"),
              region="NG", language="en")),
        ("folha", "Folha de S.Paulo", "regional", "link_out",
         dict(search="https://search.folha.uol.com.br/search?q={q}", types=("name", "web"),
              region="BR", language="pt")),
        ("clarin", "Clarín", "regional", "link_out",
         dict(search="https://www.clarin.com/buscador/?q={q}", types=("name", "web"),
              region="AR", language="es")),
        ("lanacion", "La Nación", "regional", "link_out",
         dict(search="https://www.lanacion.com.ar/buscador/?q={q}", types=("name", "web"),
              region="AR", language="es")),
        ("eltiempo", "El Tiempo", "regional", "link_out",
         dict(search="https://www.eltiempo.com/buscar?q={q}", types=("name", "web"),
              region="CO", language="es")),
        ("elcomercio", "El Comercio", "regional", "link_out",
         dict(search="https://elcomercio.pe/buscar/?q={q}", types=("name", "web"),
              region="PE", language="es")),
        ("smh", "Sydney Morning Herald", "regional", "link_out",
         dict(search="https://www.smh.com.au/search?q={q}", types=("name", "web"),
              region="AU", language="en")),
        ("nzherald", "NZ Herald", "regional", "link_out",
         dict(search="https://www.nzherald.co.nz/search/?q={q}", types=("name", "web"),
              region="NZ", language="en")),
    ])

    # People & identity indexes ------------------------------------------
    _many([
        ("github_users", "GitHub users", "people", "api",
         dict(url="https://api.github.com/search/users", search="https://github.com/search?q={q}&type=users",
              adapter="people.github", types=("name", "person", "handle", "code"))),
        ("gitlab_users", "GitLab users", "people", "api",
         dict(url="https://gitlab.com/api/v4/users", search="https://gitlab.com/search?search={q}",
              adapter="people.gitlab", types=("name", "person", "handle", "code"))),
        ("codeberg_users", "Codeberg users", "people", "api",
         dict(url="https://codeberg.org/api/v1/users/search", search="https://codeberg.org/explore/repos?q={q}",
              adapter="people.codeberg", types=("name", "person", "handle", "code"))),
        ("stackexchange", "Stack Exchange users", "people", "api",
         dict(url="https://api.stackexchange.com/2.3/users", search="https://stackoverflow.com/search?q={q}",
              adapter="people.stackexchange", types=("name", "person", "handle", "code"))),
        ("openalex_authors", "OpenAlex authors", "people", "api",
         dict(url="https://api.openalex.org/authors", search="https://openalex.org/authors?search={q}",
              adapter="people.openalex", types=("name", "person", "academic"))),
        ("semanticscholar_authors", "Semantic Scholar authors", "people", "api",
         dict(url="https://api.semanticscholar.org/graph/v1/author/search",
              search="https://www.semanticscholar.org/search?q={q}",
              adapter="people.semanticscholar", types=("name", "person", "academic"))),
        ("orcid", "ORCID", "people", "api",
         dict(url="https://pub.orcid.org/v3.0/expanded-search/", search="https://orcid.org/orcid-search/search?searchQuery={q}",
              adapter="people.orcid", types=("name", "person", "academic"))),
        ("openlibrary", "Open Library authors", "people", "api",
         dict(url="https://openlibrary.org/search/authors.json", search="https://openlibrary.org/search/authors?q={q}",
              adapter="people.openlibrary", types=("name", "person", "academic"))),
        ("crossref", "Crossref authors", "people", "api",
         dict(url="https://api.crossref.org/works", search="https://search.crossref.org/?q={q}",
              adapter="people.crossref", types=("name", "person", "academic"))),
        ("arxiv", "arXiv authors", "people", "api",
         dict(url="https://export.arxiv.org/api/query", search="https://arxiv.org/search/?query={q}&searchtype=author",
              adapter="people.arxiv", types=("name", "person", "academic"))),
        ("pubmed", "PubMed", "people", "api",
         dict(url="https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi",
              search="https://pubmed.ncbi.nlm.nih.gov/?term={q}",
              adapter="people.pubmed", types=("name", "person", "academic"))),
        ("europepmc", "Europe PMC", "people", "api",
         dict(url="https://www.ebi.ac.uk/europepmc/webservices/rest/search",
              search="https://europepmc.org/search?query={q}",
              adapter="people.europepmc", types=("name", "person", "academic"))),
        ("openaire", "OpenAIRE", "people", "api",
         dict(url="https://api.openaire.eu/search/publications",
              search="https://explore.openaire.eu/search/find?keyword={q}",
              adapter="people.openaire", types=("name", "person", "academic"))),
        ("doaj", "DOAJ", "academic", "api",
         dict(url="https://doaj.org/api/search/articles/", search="https://doaj.org/search/articles?ref=homepage-box&source=%7B%22query%22%3A%7B%22query_string%22%3A%7B%22query%22%3A%22{q}%22%7D%7D%7D",
              adapter="people.doaj", types=("name", "academic"))),
        ("datacite", "DataCite", "academic", "api",
         dict(url="https://api.datacite.org/dois", search="https://search.datacite.org/works?query={q}",
              adapter="people.datacite", types=("name", "academic", "dataset"))),
        ("zenodo", "Zenodo", "academic", "api",
         dict(url="https://zenodo.org/api/records", search="https://zenodo.org/search?q={q}",
              adapter="people.zenodo", types=("name", "academic", "dataset"))),
        ("figshare", "Figshare", "academic", "api",
         dict(url="https://api.figshare.com/v2/articles/search", search="https://figshare.com/search?q={q}",
              adapter="people.figshare", types=("name", "academic", "dataset"))),
        ("osf_users", "OSF users", "academic", "api",
         dict(url="https://api.osf.io/v2/users/", search="https://osf.io/search/?q={q}",
              adapter="people.osf", types=("name", "person", "academic"))),
        ("google_books", "Google Books", "academic", "api",
         dict(url="https://www.googleapis.com/books/v1/volumes", search="https://www.google.com/search?tbm=bks&q={q}",
              adapter="people.google_books", types=("name", "academic", "book"))),
        ("internet_archive", "Internet Archive", "academic", "api",
         dict(url="https://archive.org/advancedsearch.php", search="https://archive.org/search?query={q}",
              adapter="people.internet_archive", types=("name", "academic", "archive"))),
        ("commoncrawl", "Common Crawl index", "academic", "api",
         dict(url="https://index.commoncrawl.org/collinfo.json", search="https://index.commoncrawl.org/",
              adapter="infra.commoncrawl", types=("web", "archive"))),
        ("viaf", "VIAF", "people", "api",
         dict(url="https://viaf.org/viaf/search", search="https://viaf.org/viaf/search?query={q}",
              adapter="people.viaf", types=("name", "person", "identity"))),
        ("littlesis", "LittleSis", "people", "api",
         dict(url="https://littlesis.org/api/entities/search", search="https://littlesis.org/search?q={q}",
              adapter="people.littlesis", types=("name", "person", "records"))),
        ("dbpedia", "DBpedia", "people", "api",
         dict(url="https://dbpedia.org/sparql", search="https://dbpedia.org/fct/?q={q}",
              adapter="people.dbpedia", types=("name", "person", "identity"))),
        ("opensanctions", "OpenSanctions", "records", "api_or_html",
         dict(url="https://api.opensanctions.org/search/default", search="https://www.opensanctions.org/search/?q={q}",
              adapter="records.opensanctions", types=("name", "person", "records"),
              note="Some endpoints require a key; public site remains a link-out.")),
        ("sec_edgar", "SEC EDGAR full-text search", "records", "api",
         dict(url="https://efts.sec.gov/LATEST/search-index", search="https://www.sec.gov/cgi-bin/srqsb?text={q}",
              adapter="records.sec_edgar", types=("name", "company", "records"))),
        ("gleif", "GLEIF LEI", "records", "api",
         dict(url="https://api.gleif.org/api/v1/lei-records", search="https://search.gleif.org/#/search/{q}",
              adapter="records.gleif", types=("name", "company", "records"))),
        ("companies_house", "UK Companies House", "records", "optional_key",
         dict(url="https://api.company-information.service.gov.uk/search/companies",
              search="https://find-and-update.company-information.service.gov.uk/search?q={q}",
              requires_key=True, key_env="COMPANIES_HOUSE_KEY",
              types=("name", "company", "records"), region="GB")),
        ("opencorporates", "OpenCorporates", "records", "optional_key",
         dict(url="https://api.opencorporates.com/v0.4/companies/search",
              search="https://opencorporates.com/companies?q={q}",
              requires_key=True, key_env="OPENCORPORATES_KEY",
              types=("name", "company", "records"))),
        ("courtlistener", "CourtListener", "records", "api_or_html",
         dict(url="https://www.courtlistener.com/api/rest/v4/search/",
              search="https://www.courtlistener.com/?q={q}",
              adapter="records.courtlistener", types=("name", "person", "records"), region="US")),
        ("canlii", "CanLII", "records", "link_out",
         dict(search="https://www.canlii.org/en/#search/text={q}", types=("name", "records"), region="CA")),
        ("bailii", "BAILII", "records", "link_out",
         dict(search="https://www.bailii.org/cgi-bin/lucy_search_1.cgi?query={q}", types=("name", "records"), region="GB")),
        ("austlii", "AustLII", "records", "link_out",
         dict(search="https://www.austlii.edu.au/cgi-bin/sinosrch.cgi?query={q}", types=("name", "records"), region="AU")),
        ("hudoc", "HUDOC", "records", "link_out",
         dict(search="https://hudoc.echr.coe.int/eng?i=001-{q}", types=("name", "records"), region="EU")),
        ("indiankanoon", "Indian Kanoon", "records", "optional_key",
         dict(search="https://indiankanoon.org/search/?formInput={q}", requires_key=True,
              key_env="INDIANKANOON_KEY", types=("name", "records"), region="IN")),
        ("china_judgements", "China Judgements Online", "records", "link_out",
         dict(search="https://wenshu.court.gov.cn/website/wenshu/181217BMTKHNT2W0/index.html?pageId=1&s={q}",
              types=("name", "records"), region="CN", language="zh")),
        ("icij_offshore", "ICIJ Offshore Leaks", "records", "link_out",
         dict(search="https://offshoreleaks.icij.org/search?q={q}", types=("name", "company", "records"))),
        ("occrp_aleph", "OCCRP Aleph", "records", "optional_key",
         dict(search="https://aleph.occrp.org/search?q={q}", requires_key=True,
              key_env="ALEPH_KEY", types=("name", "company", "records"))),
        ("openownership", "OpenOwnership", "records", "link_out",
         dict(search="https://register.openownership.org/search?q={q}", types=("name", "company", "records"))),
        ("eu_transparency", "EU Transparency Register", "records", "link_out",
         dict(search="https://ec.europa.eu/transparencyregister/public/consultation/search.do?searchText={q}",
              types=("name", "company", "records"), region="EU")),
        ("uk_charity", "UK Charity Commission", "records", "link_out",
         dict(search="https://register-of-charities.charitycommission.gov.uk/charity-search/-/results/page/1/delta/20?p_p_id=uk_gov_ccew_onereg_charitydetails_web_portlet_CharityDetailsPortlet&p_p_lifecycle=0&keywords={q}",
              types=("name", "company", "records"), region="GB")),
        ("irs_tax_exempt", "IRS Tax Exempt Organization Search", "records", "link_out",
         dict(search="https://apps.irs.gov/app/eos/allSearch?ein1=&names={q}", types=("name", "company", "records"), region="US")),
        ("propublica", "ProPublica Nonprofit Explorer", "records", "api",
         dict(url="https://projects.propublica.org/nonprofits/api/v2/search.json",
              search="https://projects.propublica.org/nonprofits/search?q={q}",
              adapter="records.propublica", types=("name", "company", "records"), region="US")),
        ("fec", "FEC campaign finance", "records", "optional_key",
         dict(url="https://api.open.fec.gov/v1/candidates/search/",
              search="https://www.fec.gov/data/search/?search={q}",
              requires_key=True, key_env="FEC_API_KEY", types=("name", "person", "records"), region="US")),
        ("lda", "US Senate LDA lobbying", "records", "public_html",
         dict(url="https://lda.senate.gov/api/v1/filings/",
              search="https://lda.senate.gov/filings/public/filing/search/?search={q}",
              adapter="records.lda", types=("name", "person", "records"), region="US",
              note="LDA API currently returns 403 from some hosts; link-out remains.")),
        ("opensecrets", "OpenSecrets", "records", "optional_key",
         dict(search="https://www.opensecrets.org/search?q={q}", requires_key=True,
              key_env="OPENSECRETS_KEY", types=("name", "person", "records"), region="US")),
        ("usaspending", "USAspending.gov", "records", "api",
         dict(url="https://api.usaspending.gov/api/v2/search/spending_by_award/",
              search="https://www.usaspending.gov/search/?hash={q}",
              adapter="records.usaspending", types=("name", "company", "records"), region="US")),
        ("ted", "TED — Tenders Electronic Daily", "records", "api",
         dict(url="https://api.ted.europa.eu/v3/notices/search",
              search="https://ted.europa.eu/en/search/result?FT={q}",
              adapter="records.ted", types=("name", "company", "records"), region="EU")),
        ("brreg", "Brønnøysund Register Centre", "records", "api",
         dict(url="https://data.brreg.no/enhetsregisteret/api/enheter",
              search="https://www.brreg.no/en/", adapter="records.brreg",
              types=("name", "company", "records"), region="NO", language="no")),
        ("recherche_entreprises", "Recherche d'entreprises (FR)", "records", "api",
         dict(url="https://recherche-entreprises.api.gouv.fr/search",
              search="https://annuaire-entreprises.data.gouv.fr/",
              adapter="records.recherche_entreprises",
              types=("name", "company", "records"), region="FR", language="fr")),
        ("vies", "EU VIES VAT", "records", "api",
         dict(url="https://ec.europa.eu/taxation_customs/vies/rest-api/ms/",
              search="https://ec.europa.eu/taxation_customs/vies/#/vat-validation",
              adapter="records.vies", types=("company", "records"), region="EU")),
        ("data_gov_uk", "data.gov.uk", "records", "api",
         dict(url="https://data.gov.uk/api/3/action/package_search",
              search="https://data.gov.uk/search?q={q}", adapter="records.data_gov_uk",
              types=("name", "company", "records", "dataset"), region="GB")),
        ("data_gov_au", "data.gov.au", "records", "api",
         dict(url="https://data.gov.au/data/api/3/action/package_search",
              search="https://data.gov.au/search?q={q}", adapter="records.data_gov_au",
              types=("name", "company", "records", "dataset"), region="AU")),
        ("data_gov_ie", "data.gov.ie", "records", "api",
         dict(url="https://data.gov.ie/api/3/action/package_search",
              search="https://data.gov.ie/search?q={q}", adapter="records.data_gov_ie",
              types=("name", "company", "records", "dataset"), region="IE")),
        ("data_europa", "data.europa.eu", "records", "api",
         dict(url="https://data.europa.eu/api/hub/search/search",
              search="https://data.europa.eu/search?q={q}", adapter="records.data_europa",
              types=("name", "company", "records", "dataset"), region="EU")),
        ("federal_register", "US Federal Register", "records", "api",
         dict(url="https://www.federalregister.gov/api/v1/documents.json",
              search="https://www.federalregister.gov/documents/search?conditions%5Bterm%5D={q}",
              adapter="records.federal_register",
              types=("name", "company", "records"), region="US")),
    ])

    # Code & developer ---------------------------------------------------
    _many([
        ("github_repos", "GitHub repositories", "code", "api",
         dict(url="https://api.github.com/search/repositories", search="https://github.com/search?q={q}&type=repositories",
              adapter="code.github_repos", types=("name", "handle", "code"))),
        ("gitlab_projects", "GitLab projects", "code", "api",
         dict(url="https://gitlab.com/api/v4/projects", search="https://gitlab.com/search?search={q}",
              adapter="code.gitlab_projects", types=("name", "code"))),
        ("codeberg_repos", "Codeberg repositories", "code", "api",
         dict(url="https://codeberg.org/api/v1/repos/search", search="https://codeberg.org/explore/repos?q={q}",
              adapter="code.codeberg_repos", types=("name", "code"))),
        ("hn_algolia", "Hacker News (Algolia)", "code", "api",
         dict(url="https://hn.algolia.com/api/v1/search", search="https://hn.algolia.com/?q={q}",
              adapter="code.hn", types=("name", "handle", "code"))),
        ("devto", "DEV Community", "code", "api",
         dict(url="https://dev.to/api/articles", search="https://dev.to/search?q={q}",
              adapter="code.devto", types=("name", "handle", "code"))),
        ("lobsters", "Lobsters", "code", "api",
         dict(url="https://lobste.rs/search.json", search="https://lobste.rs/search?q={q}",
              adapter="code.lobsters", types=("name", "handle", "code"))),
        ("huggingface", "Hugging Face", "code", "api",
         dict(url="https://huggingface.co/api/models", search="https://huggingface.co/search/full-text?q={q}",
              adapter="code.huggingface", types=("name", "handle", "code", "dataset"))),
        ("npm", "npm registry", "code", "api",
         dict(url="https://registry.npmjs.org/-/v1/search", search="https://www.npmjs.com/search?q={q}",
              adapter="code.npm", types=("name", "code"))),
        ("crates", "crates.io", "code", "api",
         dict(url="https://crates.io/api/v1/crates", search="https://crates.io/search?q={q}",
              adapter="code.crates", types=("name", "code"))),
        ("dockerhub", "Docker Hub", "code", "api",
         dict(url="https://hub.docker.com/v2/search/repositories/", search="https://hub.docker.com/search?q={q}",
              adapter="code.dockerhub", types=("name", "code"))),
        ("grep_app", "grep.app", "code", "api",
         dict(url="https://grep.app/api/search", search="https://grep.app/search?q={q}",
              adapter="code.grep_app", types=("name", "code"))),
        ("searchcode", "searchcode", "code", "api",
         dict(url="https://searchcode.com/api/codesearch_I/", search="https://searchcode.com/?q={q}",
              adapter="code.searchcode", types=("name", "code"))),
        ("sourcegraph", "Sourcegraph", "code", "optional_key",
         dict(search="https://sourcegraph.com/search?q={q}", requires_key=True,
              key_env="SOURCEGRAPH_TOKEN", types=("name", "code"))),
        ("pypi", "PyPI", "code", "link_out",
         dict(search="https://pypi.org/search/?q={q}", types=("name", "code"))),
        ("rubygems", "RubyGems", "code", "api",
         dict(url="https://rubygems.org/api/v1/search.json",
              search="https://rubygems.org/search?query={q}",
              adapter="code.rubygems", types=("name", "code"))),
        ("packagist", "Packagist", "code", "api",
         dict(url="https://packagist.org/search.json",
              search="https://packagist.org/search/?q={q}",
              adapter="code.packagist", types=("name", "code"))),
        ("nuget", "NuGet", "code", "api",
         dict(url="https://azuresearch-usnc.nuget.org/query",
              search="https://www.nuget.org/packages?q={q}",
              adapter="code.nuget", types=("name", "code"))),
        ("maven", "Maven Central", "code", "api",
         dict(url="https://search.maven.org/solrsearch/select",
              search="https://search.maven.org/search?q={q}",
              adapter="code.maven", types=("name", "code"))),
        ("gopkg", "Go Packages", "code", "link_out",
         dict(search="https://pkg.go.dev/search?q={q}", types=("name", "code"))),
        ("replit", "Replit", "code", "link_out",
         dict(search="https://replit.com/search?q={q}", types=("name", "handle", "code"))),
        ("codepen", "CodePen", "code", "link_out",
         dict(search="https://codepen.io/search/pens?q={q}", types=("name", "handle", "code"))),
        ("kaggle", "Kaggle", "code", "link_out",
         dict(search="https://www.kaggle.com/search?q={q}", types=("name", "handle", "code"))),
        ("exercism", "Exercism", "code", "link_out",
         dict(search="https://exercism.org/search?q={q}", types=("name", "handle", "code"))),
        ("leetcode", "LeetCode", "code", "link_out",
         dict(search="https://leetcode.com/search/?q={q}", types=("name", "handle", "code"))),
        ("hackerone", "HackerOne", "code", "link_out",
         dict(search="https://hackerone.com/hacktivity?querystring={q}", types=("name", "handle", "code"))),
        ("bugcrowd", "Bugcrowd", "code", "link_out",
         dict(search="https://bugcrowd.com/programs?search={q}", types=("name", "code"))),
    ])

    # Social & fediverse -------------------------------------------------
    _many([
        ("bluesky", "Bluesky", "social", "api",
         dict(url="https://public.api.bsky.app/xrpc/app.bsky.actor.searchActors",
              search="https://bsky.app/search?q={q}", adapter="people.bluesky",
              types=("name", "person", "handle", "social"))),
        ("mastodon", "Mastodon (mastodon.social)", "social", "api",
         dict(url="https://mastodon.social/api/v2/search", search="https://mastodon.social/search?q={q}",
              adapter="people.mastodon", types=("name", "person", "handle", "social"))),
        ("lemmy", "Lemmy (lemmy.world)", "social", "api",
         dict(url="https://lemmy.world/api/v3/search", search="https://lemmy.world/search?q={q}",
              adapter="people.lemmy", types=("name", "person", "handle", "social"))),
        ("misskey", "Misskey", "social", "public_html",
         dict(search="https://misskey.io/search?q={q}", types=("name", "handle", "social"), region="JP")),
        ("pleroma", "Pleroma", "social", "link_out",
         dict(search="https://pleroma.social/", types=("name", "handle", "social"))),
        ("peertube", "PeerTube", "social", "link_out",
         dict(search="https://joinpeertube.org/", types=("name", "handle", "social"))),
        ("pixelfed", "Pixelfed", "social", "link_out",
         dict(search="https://pixelfed.org/", types=("name", "handle", "social"))),
        ("bookwyrm", "BookWyrm", "social", "link_out",
         dict(search="https://bookwyrm.social/", types=("name", "handle", "social"))),
        ("nostr", "Nostr public relays", "social", "link_out",
         dict(search="https://nostr.com/", types=("name", "handle", "social"))),
        ("reddit", "Reddit", "social", "api_or_html",
         dict(url="https://www.reddit.com/search.json", search="https://www.reddit.com/search/?q={q}",
              adapter="social.reddit", types=("name", "handle", "social"))),
        ("telegram_preview", "Telegram public preview", "social", "public_html",
         dict(url="https://t.me/s/", search="https://t.me/s/{q}", adapter="social.telegram",
              types=("name", "handle", "social"))),
        ("vk", "VK", "social", "link_out",
         dict(search="https://vk.com/search?c[q]={q}&c[section]=people", types=("name", "handle", "social"), region="RU")),
        ("okru", "OK.ru", "social", "link_out",
         dict(search="https://ok.ru/search?st.query={q}", types=("name", "handle", "social"), region="RU")),
        ("weibo", "Weibo", "social", "public_html",
         dict(search="https://s.weibo.com/weibo?q={q}", adapter="social.weibo",
              types=("name", "handle", "social"), region="CN", language="zh")),
        ("douyin", "Douyin", "social", "link_out",
         dict(search="https://www.douyin.com/search/{q}", types=("name", "handle", "social"), region="CN", language="zh")),
        ("zhihu", "Zhihu", "social", "link_out",
         dict(search="https://www.zhihu.com/search?type=content&q={q}", types=("name", "handle", "social"), region="CN", language="zh")),
        ("douban", "Douban", "social", "link_out",
         dict(search="https://www.douban.com/search?q={q}", types=("name", "handle", "social"), region="CN", language="zh")),
        ("bilibili", "Bilibili", "social", "link_out",
         dict(search="https://search.bilibili.com/all?keyword={q}", types=("name", "handle", "social"), region="CN", language="zh")),
        ("naver_blog", "Naver Blog", "social", "link_out",
         dict(search="https://section.blog.naver.com/Search/Post.naver?pageNo=1&rangeType=ALL&orderBy=sim&keyword={q}",
              types=("name", "handle", "social"), region="KR", language="ko")),
        ("tistory", "Tistory", "social", "link_out",
         dict(search="https://www.tistory.com/search?q={q}", types=("name", "handle", "social"), region="KR", language="ko")),
        ("daum_cafe", "Daum Cafe", "social", "link_out",
         dict(search="https://search.daum.net/search?w=tot&q={q}", types=("name", "handle", "social"), region="KR", language="ko")),
        ("line", "LINE", "social", "link_out",
         dict(search="https://line.me/ti/p/~{q}", types=("name", "handle", "social"), region="JP")),
        ("pixiv", "Pixiv", "social", "link_out",
         dict(search="https://www.pixiv.net/en/search?word={q}", types=("name", "handle", "social"), region="JP", language="ja")),
        ("niconico", "Niconico", "social", "link_out",
         dict(search="https://www.nicovideo.jp/search/{q}", types=("name", "handle", "social"), region="JP", language="ja")),
        ("mixi", "Mixi", "social", "link_out",
         dict(search="https://mixi.jp/search?q={q}", types=("name", "handle", "social"), region="JP", language="ja")),
        ("ameba", "Ameba", "social", "link_out",
         dict(search="https://search.ameba.jp/search.html?q={q}", types=("name", "handle", "social"), region="JP", language="ja")),
        ("hatena", "Hatena", "social", "link_out",
         dict(search="https://b.hatena.ne.jp/search?q={q}", types=("name", "handle", "social"), region="JP", language="ja")),
        ("gab", "Gab", "social", "link_out",
         dict(search="https://gab.com/search?q={q}", types=("name", "handle", "social"))),
        ("gettr", "GETTR", "social", "link_out",
         dict(search="https://gettr.com/search?q={q}", types=("name", "handle", "social"))),
        ("truthsocial", "Truth Social", "social", "link_out",
         dict(search="https://truthsocial.com/search?q={q}", types=("name", "handle", "social"))),
        ("parler", "Parler", "social", "link_out",
         dict(search="https://parler.com/search?q={q}", types=("name", "handle", "social"))),
        ("rumble", "Rumble", "social", "link_out",
         dict(search="https://rumble.com/search/video?q={q}", types=("name", "handle", "social"))),
        ("odysee", "Odysee", "social", "link_out",
         dict(search="https://odysee.com/$/search?q={q}", types=("name", "handle", "social"))),
        ("youtube", "YouTube", "social", "link_out",
         dict(search="https://www.youtube.com/results?search_query={q}", types=("name", "handle", "social"))),
        ("tiktok", "TikTok", "social", "link_out",
         dict(search="https://www.tiktok.com/search?q={q}", types=("name", "handle", "social"))),
        ("instagram", "Instagram", "social", "link_out",
         dict(search="https://www.instagram.com/web/search/topsearch/?query={q}", types=("name", "handle", "social"))),
        ("facebook", "Facebook", "social", "link_out",
         dict(search="https://www.facebook.com/search/top?q={q}", types=("name", "handle", "social"))),
        ("x_twitter", "X/Twitter", "social", "link_out",
         dict(search="https://x.com/search?q={q}", types=("name", "handle", "social"))),
        ("linkedin", "LinkedIn", "social", "link_out",
         dict(search="https://www.linkedin.com/search/results/people/?keywords={q}", types=("name", "handle", "social"))),
        ("threads", "Threads", "social", "link_out",
         dict(search="https://www.threads.net/search?q={q}", types=("name", "handle", "social"))),
        ("pinterest", "Pinterest", "social", "link_out",
         dict(search="https://www.pinterest.com/search/pins/?q={q}", types=("name", "handle", "social"))),
        ("tumblr", "Tumblr", "social", "link_out",
         dict(search="https://www.tumblr.com/search/{q}", types=("name", "handle", "social"))),
        ("quora", "Quora", "social", "link_out",
         dict(search="https://www.quora.com/search?q={q}", types=("name", "handle", "social"))),
        ("medium", "Medium", "social", "link_out",
         dict(search="https://medium.com/search?q={q}", types=("name", "handle", "social"))),
        ("substack", "Substack", "social", "link_out",
         dict(search="https://substack.com/search/{q}", types=("name", "handle", "social"))),
        ("aboutme", "About.me", "social", "link_out",
         dict(search="https://about.me/search?q={q}", types=("name", "handle", "social"))),
        ("keybase", "Keybase", "social", "public_html",
         dict(search="https://keybase.io/search?q={q}", adapter="social.keybase",
              types=("name", "handle", "social"))),
    ])

    # Image / media ------------------------------------------------------
    _many([
        ("google_lens", "Google Lens", "image", "link_out",
         dict(search="https://lens.google.com/uploadbyurl?url={q}", types=("image", "media"))),
        ("bing_visual", "Bing Visual Search", "image", "link_out",
         dict(search="https://www.bing.com/images/searchbyimage/upload?imgurl={q}", types=("image", "media"))),
        ("yandex_images", "Yandex Images", "image", "link_out",
         dict(search="https://yandex.com/images/search?rpt=imageview&url={q}", types=("image", "media"))),
        ("tineye", "TinEye", "image", "optional_key",
         dict(search="https://tineye.com/search?url={q}", requires_key=True,
              key_env="TINEYE_API_KEY", types=("image", "media"))),
        ("saucenao", "SauceNAO", "image", "optional_key",
         dict(search="https://saucenao.com/search.php?url={q}", requires_key=True,
              key_env="SAUCENAO_API_KEY", types=("image", "media"))),
        ("iqdb", "IQDB", "image", "link_out",
         dict(search="https://iqdb.org/?url={q}", types=("image", "media"))),
        ("ascii2d", "ascii2d", "image", "link_out",
         dict(search="https://ascii2d.net/search/url/{q}", types=("image", "media"), region="JP")),
        ("baidu_images", "Baidu Images", "image", "link_out",
         dict(search="https://graph.baidu.com/details?image_url={q}", types=("image", "media"), region="CN")),
        ("sogou_images", "Sogou Images", "image", "link_out",
         dict(search="https://pic.sogou.com/ris?query={q}", types=("image", "media"), region="CN")),
        ("karma_decay", "Karma Decay", "image", "link_out",
         dict(search="https://karmadecay.com/search?q={q}", types=("image", "media"), region="US")),
        ("trace_moe", "Trace.moe", "image", "api",
         dict(url="https://api.trace.moe/search", search="https://trace.moe/?url={q}",
              adapter="image.trace_moe", types=("image", "media", "video"))),
        ("imgops", "ImgOps", "image", "link_out",
         dict(search="https://imgops.com/{q}", types=("image", "media"))),
        ("exifdata", "ExifData", "image", "link_out",
         dict(search="https://exifdata.com/", types=("image", "media"))),
        ("forensically", "Forensically", "image", "link_out",
         dict(search="https://29a.ch/photo-forensics/", types=("image", "media"))),
        ("imgverify", "Xaxglog image provenance", "image", "api",
         dict(url="", search="", adapter="image.imgverify", types=("image", "media"),
              note="Local perceptual hash / near-duplicate provenance; no upload.")),
    ])

    # Geospatial / infrastructure ---------------------------------------
    _many([
        ("dns_google", "Google DNS-over-HTTPS", "infrastructure", "api",
         dict(url="https://dns.google/resolve", search="https://dns.google/",
              adapter="infra.dns", types=("domain", "ip", "infrastructure"))),
        ("crtsh", "crt.sh certificate transparency", "infrastructure", "api",
         dict(url="https://crt.sh/", search="https://crt.sh/?q={q}",
              adapter="infra.crtsh", types=("domain", "infrastructure"))),
        ("urlscan", "urlscan.io", "infrastructure", "api",
         dict(url="https://urlscan.io/api/v1/search/", search="https://urlscan.io/search/#{q}",
              adapter="infra.urlscan", types=("domain", "ip", "web"))),
        ("wayback", "Wayback Machine CDX", "infrastructure", "api",
         dict(url="https://web.archive.org/cdx/search/cdx", search="https://web.archive.org/web/*/{q}",
              adapter="infra.wayback", types=("web", "archive", "domain"))),
        ("ipapi", "ip-api.com", "infrastructure", "api",
         dict(url="http://ip-api.com/json/", search="https://ip-api.com/#{q}",
              adapter="infra.ipapi", types=("ip", "infrastructure"))),
        ("rdap", "RDAP", "infrastructure", "api",
         dict(url="https://rdap.org/domain/", search="https://rdap.org/domain/{q}",
              adapter="infra.rdap", types=("domain", "infrastructure"))),
        ("nominatim", "OpenStreetMap Nominatim", "infrastructure", "api",
         dict(url="https://nominatim.openstreetmap.org/search", search="https://www.openstreetmap.org/search?query={q}",
              adapter="infra.nominatim", types=("geo", "place", "infrastructure"))),
        ("restcountries", "countries.dev", "infrastructure", "api",
         dict(url="https://countries.dev/name/", search="https://countries.dev/name/{q}",
              adapter="infra.restcountries", types=("geo", "place", "infrastructure"),
              note="Keyless country/place data; REST Countries v3/v5 now requires a key.")),
        ("worldbank", "World Bank", "infrastructure", "api",
         dict(url="https://api.worldbank.org/v2/country", search="https://data.worldbank.org/",
              adapter="infra.worldbank", types=("geo", "place", "records"))),
        ("gdelt", "GDELT", "monitoring", "api",
         dict(url="https://api.gdeltproject.org/api/v2/doc/doc", search="https://www.gdeltproject.org/",
              adapter="people.gdelt", types=("name", "news", "monitoring"))),
        ("opensky", "OpenSky Network", "infrastructure", "api",
         dict(url="https://opensky-network.org/api/states/all", search="https://opensky-network.org/network/explorer",
              adapter="infra.opensky", types=("flight", "infrastructure"))),
        ("bgpview", "BGPView", "infrastructure", "api",
         dict(url="https://api.bgpview.io/", search="https://bgpview.io/", adapter="infra.bgpview",
              types=("ip", "domain", "infrastructure"))),
        ("team_cymru", "Team Cymru", "infrastructure", "link_out",
         dict(search="https://www.team-cymru.com/", types=("ip", "infrastructure"))),
        ("robtex", "Robtex", "infrastructure", "link_out",
         dict(search="https://www.robtex.com/?q={q}", types=("ip", "domain", "infrastructure"))),
        ("urlhaus", "URLhaus", "monitoring", "link_out",
         dict(search="https://urlhaus.abuse.ch/browse.php?search={q}", types=("domain", "ip", "monitoring"))),
        ("otx", "AlienVault OTX", "monitoring", "optional_key",
         dict(search="https://otx.alienvault.com/browse/global/pulses?q={q}", requires_key=True,
              key_env="OTX_API_KEY", types=("domain", "ip", "monitoring"))),
        ("malwarebazaar", "MalwareBazaar", "monitoring", "link_out",
         dict(search="https://bazaar.abuse.ch/browse.php?search={q}", types=("hash", "monitoring"))),
        ("openphish", "OpenPhish", "monitoring", "link_out",
         dict(search="https://openphish.com/", types=("domain", "monitoring"))),
        ("phishtank", "PhishTank", "monitoring", "optional_key",
         dict(search="https://phishtank.org/", requires_key=True, key_env="PHISHTANK_KEY",
              types=("domain", "monitoring"))),
        ("shodan", "Shodan", "infrastructure", "optional_key",
         dict(search="https://www.shodan.io/search?query={q}", requires_key=True,
              key_env="SHODAN_API_KEY", types=("ip", "domain", "infrastructure"))),
        ("censys", "Censys", "infrastructure", "optional_key",
         dict(search="https://search.censys.io/search?resource=hosts&q={q}", requires_key=True,
              key_env="CENSYS_API_KEY", types=("ip", "domain", "infrastructure"))),
        ("virustotal", "VirusTotal", "monitoring", "optional_key",
         dict(search="https://www.virustotal.com/gui/search/{q}", requires_key=True,
              key_env="VIRUSTOTAL_API_KEY", types=("domain", "ip", "hash", "monitoring"))),
        ("abuseipdb", "AbuseIPDB", "monitoring", "optional_key",
         dict(search="https://www.abuseipdb.com/check/{q}", requires_key=True,
              key_env="ABUSEIPDB_API_KEY", types=("ip", "monitoring"))),
        ("ipinfo", "IPinfo", "infrastructure", "optional_key",
         dict(search="https://ipinfo.io/{q}", requires_key=True,
              key_env="IPINFO_TOKEN", types=("ip", "infrastructure"))),
        ("securitytrails", "SecurityTrails", "infrastructure", "optional_key",
         dict(search="https://securitytrails.com/domain/{q}/dns", requires_key=True,
              key_env="SECURITYTRAILS_KEY", types=("domain", "infrastructure"))),
        ("certstream", "Certificate Transparency stream", "monitoring", "api",
         dict(url="https://certstream.calidog.io/", search="https://certstream.calidog.io/",
              adapter="infra.certstream", types=("domain", "monitoring"))),
        ("ripe_stat", "RIPE Stat", "infrastructure", "api",
         dict(url="https://stat.ripe.net/data/searchcomplete/data.json",
              search="https://stat.ripe.net/", adapter="infra.ripe_stat",
              types=("ip", "domain", "infrastructure"), region="EU")),
        ("shodan_internetdb", "Shodan InternetDB", "infrastructure", "api",
         dict(url="https://internetdb.shodan.io/",
              search="https://www.shodan.io/host/{q}", adapter="infra.shodan_internetdb",
              types=("ip", "infrastructure"))),
    ])

    # Monitoring / feeds ------------------------------------------------
    _many([
        ("rss", "RSS / Atom feeds", "monitoring", "public_html",
         dict(url="", search="", adapter="monitoring.rss", types=("news", "monitoring"),
              note="Operator-supplied public feeds; no login or private feeds.")),
        ("gdelt_news", "GDELT news events", "monitoring", "api",
         dict(url="https://api.gdeltproject.org/api/v2/doc/doc", search="https://www.gdeltproject.org/",
              adapter="people.gdelt", types=("name", "news", "monitoring"))),
        ("wayback_watch", "Wayback change watch", "monitoring", "api",
         dict(url="https://web.archive.org/cdx/search/cdx", search="https://web.archive.org/web/*/{q}",
              adapter="infra.wayback", types=("web", "monitoring"))),
        ("urlscan_watch", "urlscan change watch", "monitoring", "api",
         dict(url="https://urlscan.io/api/v1/search/", search="https://urlscan.io/search/#{q}",
              adapter="infra.urlscan", types=("web", "monitoring"))),
        ("telegram_watch", "Telegram public channel watch", "monitoring", "public_html",
         dict(search="https://t.me/s/{q}", adapter="social.telegram", types=("social", "monitoring"))),
        ("certstream_watch", "Certificate transparency watch", "monitoring", "api",
         dict(url="https://certstream.calidog.io/", search="https://certstream.calidog.io/",
              adapter="infra.certstream", types=("domain", "monitoring"))),
        ("urlhaus_watch", "URLhaus watch", "monitoring", "link_out",
         dict(search="https://urlhaus.abuse.ch/browse.php?search={q}", types=("domain", "monitoring"))),
        ("otx_watch", "OTX pulses watch", "monitoring", "optional_key",
         dict(search="https://otx.alienvault.com/browse/global/pulses?q={q}", requires_key=True,
              key_env="OTX_API_KEY", types=("domain", "ip", "monitoring"))),
        ("malwarebazaar_watch", "MalwareBazaar watch", "monitoring", "link_out",
         dict(search="https://bazaar.abuse.ch/browse.php?search={q}", types=("hash", "monitoring"))),
        ("openphish_watch", "OpenPhish watch", "monitoring", "link_out",
         dict(search="https://openphish.com/", types=("domain", "monitoring"))),
    ])


def _build_social_platforms():
    """Add every platform in socialscrape's public catalog.

    These are public profile/search pages, not private APIs.  They are marked
    ``public_html`` when a profile URL exists and ``link_out`` otherwise, so
    they never inflate the "verified API" count.
    """
    try:
        from modules.socialscrape import socialscrape as SS
        platforms = SS.catalog().get("platform_list") or []
    except Exception:
        return
    cat_map = {
        "social": "social", "code": "code", "professional": "social",
        "creative": "social", "video": "social", "music": "social",
        "gaming": "social", "shopping": "social", "academic": "academic",
        "lifestyle": "social", "regional": "social", "news": "monitoring",
        "blog": "social", "forum": "social", "messaging": "social",
    }
    for p in platforms:
        name = p.get("name") or ""
        if not name:
            continue
        cat = cat_map.get(p.get("category") or "", "social")
        profile = p.get("profile_url") or ""
        search = p.get("search_template") or ""
        access = "public_html" if profile else "link_out"
        _add(
            "social_" + _slug(name), name, cat, access,
            region=p.get("region") or "global",
            language=p.get("language") or "en",
            types=("name", "handle", "social") if cat == "social" else
                  ("name", "handle", cat),
            url=profile or search,
            search=search,
            profile_url=profile,
            adapter="socialscrape.page" if profile else None,
            status="cataloged",
            domains=p.get("domains") or [],
            note="Public platform page from the socialscrape catalog; login/captcha walls are reported as blocked.",
        )


_build_core()
_build_social_platforms()


# ---------------------------------------------------------------- query API
def get(source_id):
    return REGISTRY.get(_slug(source_id))


def sources():
    return list(REGISTRY.values())


def select(*, types=None, categories=None, region=None, access=None,
           status=None, queryable=False, limit=None):
    """Filter the registry.

    ``types`` matches any requested type; ``categories``/``access``/``status``
    match exact values.  ``queryable=True`` keeps only api/public_html/
    api_or_html sources that have an adapter or are verified.
    """
    wanted_types = {t.lower() for t in types} if isinstance(types, (list, tuple, set)) else (
        {types.lower()} if types else set())
    wanted_categories = {c.lower() for c in categories} if isinstance(categories, (list, tuple, set)) else (
        {categories.lower()} if categories else set())
    wanted_access = {a.lower() for a in access} if isinstance(access, (list, tuple, set)) else (
        {access.lower()} if access else set())
    wanted_status = {s.lower() for s in status} if isinstance(status, (list, tuple, set)) else (
        {status.lower()} if status else set())
    out = []
    for src in REGISTRY.values():
        if wanted_types and not (set(src["types"]) & wanted_types):
            continue
        if wanted_categories and src["category"] not in wanted_categories:
            continue
        if region and region not in ("all", "*") and src["region"] not in (region, "global"):
            continue
        if wanted_access and src["access"] not in wanted_access:
            continue
        if wanted_status and src["status"] not in wanted_status:
            continue
        if queryable and not (src["adapter"] or src["verified"]):
            continue
        out.append(src)
    out.sort(key=lambda s: (s["category"], s["label"].lower()))
    return out[:limit] if limit else out


def plan(kind="person", depth="standard", country=None, include_social=True,
         include_link_out=True):
    """Return a source plan for a target kind and depth.

    The plan is metadata only; execution is done by ``modules.identity``.
    """
    kind = (kind or "person").lower()
    if kind in ("person", "name", "identity"):
        cats = ["people", "web", "academic", "code", "records"]
        if include_social:
            cats.append("social")
        if depth == "deep":
            cats += ["regional", "image", "monitoring"]
    elif kind in ("handle", "username", "social"):
        cats = ["social", "code", "web", "people"]
        if depth == "deep":
            cats += ["regional"]
    elif kind in ("company", "organization", "org"):
        cats = ["records", "web", "people"]
    elif kind in ("domain", "ip", "infrastructure"):
        cats = ["infrastructure", "web", "monitoring"]
    else:
        cats = ["web", "people", "records", "academic", "code", "social"]
    picked = select(types=(kind, "name") if kind in ("person", "name", "identity") else (kind,),
                    categories=cats, region=country, limit=None)
    if not include_link_out:
        picked = [s for s in picked if s["access"] != "link_out"]
    if depth == "quick":
        picked = [s for s in picked if s["adapter"] or s["verified"]][:60]
    elif depth == "standard":
        picked = picked[:160]
    return {
        "kind": kind,
        "depth": depth,
        "country": country or "all",
        "categories": cats,
        "count": len(picked),
        "sources": picked,
    }


def search_links(query, *, types=None, categories=None, region=None, limit=250):
    """Build public search/profile links for a query (never an automatic hit)."""
    q = (query or "").strip()
    if not q:
        return []
    quoted = urllib.parse.quote(q)
    out = []
    for src in select(types=types, categories=categories, region=region):
        tmpl = src.get("search") or ""
        if not tmpl or "{q}" not in tmpl:
            continue
        out.append({
            "id": src["id"],
            "label": src["label"],
            "category": src["category"],
            "access": src["access"],
            "status": src["status"],
            "url": tmpl.replace("{q}", quoted),
        })
        if len(out) >= limit:
            break
    return out


def catalog(include_sources=True, limit=None):
    by_category = {k: len(v) for k, v in _BY_CATEGORY.items()}
    by_access = {k: len(v) for k, v in _BY_ACCESS.items()}
    by_status = {k: len(v) for k, v in _BY_STATUS.items()}
    all_sources = sources()
    if limit:
        all_sources = all_sources[:limit]
    return {
        "total": len(REGISTRY),
        "by_category": by_category,
        "by_access": by_access,
        "by_status": by_status,
        "verified": by_status.get("verified", 0),
        "adapter": by_status.get("adapter", 0),
        "optional_key": by_status.get("optional_key", 0),
        "link_out": by_status.get("link_out", 0),
        "blocked": by_status.get("blocked", 0),
        "error": by_status.get("error", 0),
        "cataloged": by_status.get("cataloged", 0),
        "queryable": sum(1 for s in REGISTRY.values() if s["adapter"] or s["verified"]),
        "categories": [{"id": k, "label": CATEGORY_LABELS.get(k, k), "count": v}
                       for k, v in sorted(by_category.items())],
        "access_modes": list(ACCESS_MODES),
        "sources": all_sources if include_sources else [],
        "note": ("Verified means live-checked from this host. Adapter means code exists "
                 "but a live check is still recommended. Link-out and blocked sources "
                 "are never counted as automatic hits."),
    }


def summary():
    c = catalog(include_sources=False)
    c.pop("sources", None)
    return c
