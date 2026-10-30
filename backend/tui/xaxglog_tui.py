#!/usr/bin/env python3
"""Xaxglog CYBERDECK TUI — terminal console for the Xaxglog OSINT platform.

Zero external dependencies: stdlib `cmd` + ANSI escape codes. Talks to the
running Flask API (http://127.0.0.1:5000/api by default; XAXGLOG_API env var
overrides). Login once with `login <user> <pass>`; the JWT is kept in memory
and attached to every request.

``Xaxglog`` is open-source intelligence aggregation: this console exposes only
the lawful, public-source endpoints (deep search, social, cases, alerts).

Commands
--------
  deep <query>          auto-detected deep search (email/ip/domain/phone/person/handle)
  person <query>        person/handle sweep
  social <query>        social footprint + web discovery
  ssearch <query>       socialscrape: broad public social-media search
  scatalog              socialscrape platform catalog summary
  cases                 list cases
  alerts [N]            recent unacknowledged alerts (score 30+)
  case <id>             open a case (artifacts/entities)
  raw <METHOD> <path> [json-body]   raw API call, pretty-printed
  status                API health banner
  login <user> <pass>   authenticate (viewer/analyst/admin)
  help                  command list

Colour legend: magenta = command echo · cyan = links/handles · green = ok
· amber = warning/blocked · dim = metadata.

Run:  python3 backend/tui/xaxglog_tui.py            (with backend running)
      ./start.sh --tui                              (from repo root)
"""
import cmd
import json
import os
import shlex
import sys
import urllib.error
import urllib.parse
import urllib.request

# ANSI palette (no deps; degrade gracefully when not a TTY)
_R = sys.stdout.isatty()


def _c(code, text):
    if sys.platform == "win32":
        os.system("")           # enable VT sequences on modern Windows
    return "\033[%sm%s\033[0m" % (code, text) if _R else str(text)


def R(t):     return _c("95", t)     # magenta / command echo
def C(t):     return _c("96", t)     # cyan / links
def G(t):     return _c("92", t)     # green / ok
def Y(t):     return _c("93", t)     # amber / warning
def RD(t):    return _c("91", t)     # red / error
def DIM(t):   return _c("90", t)     # dim metadata
def BOLD(t):  return _c("1", t)

BANNER = r"""
 █  █ █▀▀█ █▀▀▄ █▀▀ █▀▀▀ █▀▀█ █▀▀█ █▀▀ █▀▀█
 █▄▄█ █  █ █  █ ▀▀█ █    █▄▄▀ █▄▄█ ▀▀█ █  █
 ▄  ▄ █▄▄█ █▄▄▀ ▄▄█ █▄▄▄ █ ▄▄ █  █ ▄▄█ █▄▄█
 ─── CYBERDECK TUI · public-source OSINT ───
"""

API_BASE = os.environ.get("XAXGLOG_API", "http://127.0.0.1:5000/api")


class Deck(cmd.Cmd):
    intro = C(BANNER) + DIM("type ") + BOLD("help") + DIM(" for commands · ") + \
        BOLD("status") + DIM(" to check the link\n")
    prompt = R("xaxglog> ")
    doc_header = "CYBERDECK COMMANDS"

    def __init__(self):
        super().__init__()
        self.token = ""
        self.user = ""

    # ------------------------------------------------------------- transport
    def _headers(self):
        h = {"Accept": "application/json", "User-Agent": "Xaxglog-TUI/1.0"}
        if self.token:
            h["Authorization"] = "Bearer " + self.token
        return h

    def _call(self, method, path, body=None, label=""):
        url = API_BASE + path if path.startswith("/") else API_BASE + "/" + path
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            method = method.upper()
            if method == "GET":
                method = "POST"
        req = urllib.request.Request(url, data=data, headers=self._headers(),
                                     method=method.upper())
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=180) as resp:
                out = json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            try:
                out = json.loads(e.read().decode() or "{}")
                out.setdefault("http", e.code)
            except Exception:
                out = {"http": e.code, "error": "HTTP %s" % e.code}
        except Exception as e:
            out = {"error": str(e)[:160]}
            return out
        if label:
            print(DIM("· " + label))
        return out

    # ---------------------------------------------------------------- status
    def do_status(self, line):
        """Link check: GET /health."""
        r = self._call("GET", "/health")
        if r.get("status") == "ok":
            print(G("LINK OK") + DIM("  ") + json.dumps(
                {k: r[k] for k in r if k != "status"}))
        else:
            print(RD("LINK DOWN") + DIM(" — is the backend on %s? (%s)"
                                       % (API_BASE, r.get("error", ""))))

    def do_login(self, line):
        """login <user> <pass> — authenticate; roles viewer/analyst/admin."""
        try:
            user, pwd = shlex.split(line)
        except ValueError:
            print(Y("usage: login <username> <password>"))
            return
        r = self._call("POST", "/auth/login",
                       {"username": user, "password": pwd})
        if r.get("token"):
            self.token = r["token"]
            self.user = r.get("user") or {}
            self.prompt = R("xaxglog[%s]> " % self.user.get("username", "?"))
            print(G("AUTH OK") + DIM("  role=") +
                  BOLD(self.user.get("role", "")))
        else:
            print(RD("AUTH FAILED: %s" % r.get("error", r.get("http", "?"))))

    def _require_auth(self):
        if not self.token:
            print(Y("→ not authenticated; run ") + BOLD("login <user> <pass>"))
            return False
        return True

    # ------------------------------------------------------------- deep deck
    def do_deep(self, line):
        """deep <query> — auto type-detection deep search."""
        if not (self._require_auth() and line.strip()):
            return
        r = self._call("POST", "/deep/search", {"query": line.strip()},
                       label="deep scan…")
        self._print_deep(r)

    def _print_deep(self, r):
        if r.get("error"):
            print(RD(r["error"]))
            return
        print(G(" detected: %s " % r.get("detected_type", "?")).center(64, "─"))
        for grp, res in (r.get("results") or {}).items():
            hits = self._rowize(res)
            print(Y("\n ◆ %s — %d hit(s)" % (grp.upper(), len(hits))))
            for row in hits[:15]:
                self._print_row(row)
            if len(hits) > 15:
                print(DIM("   … %d more (raw: use `raw` command to inspect)"
                          % (len(hits) - 15)))

    @staticmethod
    def _rowize(node, out=None, depth=0):
        if out is None:
            out = []
        if node is None or depth > 5 or len(out) > 200:
            return out
        if isinstance(node, list):
            for x in node:
                Deck._rowize(x, out, depth + 1)
            return out
        if isinstance(node, dict):
            if node.get("url") or node.get("title") or node.get("name"):
                out.append(node)
                return out
            for v in node.values():
                if isinstance(v, (dict, list)):
                    Deck._rowize(v, out, depth + 1)
        return out

    @staticmethod
    def _print_row(row):
        title = row.get("title") or row.get("name") or row.get("display_name") \
            or row.get("login") or "—"
        plat = row.get("platform") or row.get("source") or "source"
        when = (row.get("published") or row.get("seen") or "")[:10]
        bits = [R("[%s]" % plat), BOLD(str(title)[:72])]
        if row.get("author"):
            bits.append(C("@" + str(row["author"]).lstrip("@")))
        if row.get("match") is not None:
            bits.append(DIM("match %s" % row["match"]))
        if when:
            bits.append(DIM(when))
        print("  " + " ".join(str(b) for b in bits))
        url = row.get("url") or ""
        if url:
            print("    " + C(str(url)[:96]))
        snip = row.get("snippet") or row.get("description") or row.get("bio") or ""
        if snip:
            print("    " + DIM(str(snip)[:110]))

    def do_person(self, line):
        """person <query> — handle/full-name people sweep."""
        if not (self._require_auth() and line.strip()):
            return
        r = self._call("POST", "/deep/person", {"query": line.strip()},
                       label="people sweep…")
        self._print_deep(r)

    def do_social(self, line):
        """social <query> — social footprint (profiles + web discovery)."""
        if not (self._require_auth() and line.strip()):
            return
        r = self._call("POST", "/deep/social",
                       {"query": line.strip()}, label="social deck…")
        self._print_deep({"detected_type": "social", "results": {"social": r}})

    def do_ssearch(self, line):
        """ssearch <query> — broad public social-media search (187 platforms)."""
        if not (self._require_auth() and line.strip()):
            return
        r = self._call("POST", "/socialscrape/search",
                       {"query": line.strip(), "limit": 30},
                       label="social grid sweep…")
        if r.get("error"):
            print(RD(r["error"]))
            return
        print(G(" status: %s" % r.get("status", "?")))
        summ = r.get("summary") or {}
        print(DIM("  results=%s engines_ok=%s blocked=%s links=%s"
                  % (summ.get("results"), summ.get("engines_ok"),
                     summ.get("engines_blocked"), summ.get("search_links"))))
        for row in (r.get("results") or [])[:15]:
            self._print_row(row)
        tags = r.get("hashtags") or []
        men = r.get("mentions") or []
        if tags:
            print("  " + Y("#hashtags: ") + DIM(" ".join("#" + t for t in tags[:12])))
        if men:
            print("  " + Y("@mentions: ") + DIM(" ".join("@" + m for m in men[:12])))
        for link in (r.get("search_links") or [])[:10]:
            print("   · " + DIM(link.get("platform", "")) + " " + C(link.get("url", "")))

    def do_scatalog(self, line):
        """socialscrape catalog summary."""
        r = self._call("GET", "/socialscrape/catalog")
        if r.get("error"):
            print(RD(str(r["error"])))
            return
        print(G(" platforms %s " % r.get("platforms")).center(50, "─"))
        print(DIM("  searchable: %s · regions: %s" % (
            r.get("searchable_platforms"), ",".join(
                "%s:%s" % kv for kv in sorted((r.get("by_region") or {}).items())))))

    # ------------------------------------------------------------- cases deck
    def do_cases(self, line):
        """list investigation cases."""
        if not self._require_auth():
            return
        r = self._call("GET", "/cases")
        rows = r if isinstance(r, list) else (r.get("cases") or [])
        print(G(" CASES %d " % len(rows)).center(60, "─"))
        for cse in rows[:25]:
            print("  " + BOLD("#%s" % cse.get("id")) + " " +
                  R(cse.get("case_number") or "") + " " +
                  C(str(cse.get("name") or "")[:40]) + " " +
                  DIM(str(cse.get("status") or "")))

    def do_alerts(self, line):
        """alerts [n] — recent indicator alerts (min score 30)."""
        if not self._require_auth():
            return
        r = self._call("GET", "/alerts?min_score=30&unack=1")
        rows = r.get("alerts") if isinstance(r, dict) else r
        if rows is None:
            rows = []
        n = int(line or 10)
        print(G(" ALERTS %d " % len(rows)).center(60, "─"))
        for a in rows[:max(1, n)]:
            sev = a.get("severity") or "info"
            col = RD if sev in ("critical", "high") else (Y if sev == "medium" else DIM)
            print("  " + col("[%s]" % sev) + " " + BOLD(str(a.get("message") or "")[:80]) +
                  DIM("  %s" % (a.get("ts") or "")[:19]))

    def do_case(self, line):
        """case <id> — open one case (snapshot + entity counts)."""
        if not (self._require_auth() and line.strip().isdigit()):
            print(Y("usage: case <id>"))
            return
        r = self._call("GET", "/cases/%s" % line.strip())
        if r.get("error"):
            print(RD(r["error"]))
            return
        print(G(" CASE %s " % r.get("case_number", line.strip())).center(56, "─"))
        print("  " + C(r.get("name") or "") + DIM(" · " + str(r.get("status") or "")))
        print("  " + DIM((r.get("description") or "")[:100]))
        ents = self._call("GET", "/cases/%s/graph" % line.strip())
        print(DIM("  graph: %s nodes / %s links" %
                  (ents.get("node_count", "?"), ents.get("link_count", "?"))))

    # -------------------------------------------------------------- raw API
    def do_raw(self, line):
        """raw <GET|POST> <path> [json-body]  — raw API call, pretty-printed.

        e.g.  raw GET /deep/sources
              raw POST /deep/location {"query":"jane_doe"}
        """
        parts = shlex.split(line)
        if len(parts) < 2:
            print(Y("usage: raw <GET|POST> <path> [json]"))
            return
        method, path = parts[0].upper(), parts[1]
        body = {}
        if len(parts) > 2:
            try:
                body = json.loads(" ".join(parts[2:]))
            except Exception as e:
                print(RD("bad json: %s" % e))
                return
        r = self._call(method, path, body if body else None)
        print(json.dumps(r, indent=2, ensure_ascii=False)[:6000])

    # ---------------------------------------------------------------- misc
    def do_theme(self, line):
        """print the colour legend."""
        print("legend: " + R("[" + "cmd" + "] ") + C("links ") + G("ok ") +
              Y("warn ") + RD("err ") + DIM("metadata"))

    def do_EOF(self):
        return self.do_exit("")

    def do_exit(self, line):
        """leave the deck."""
        print(DIM("deck down. stay lawful."))
        return True


if __name__ == "__main__":
    if not sys.stdout.isatty():
        print(RD("stdin/stdout is not a TTY — an interactive terminal is required."))
        sys.exit(1)
    Deck().cmdloop()
