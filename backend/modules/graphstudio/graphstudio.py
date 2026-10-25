"""Xaxglog graphstudio — force-directed entity graph layout for the console.

The cases module already stores entities + edges; this module computes a
readable 2D layout server-side (pure python: Fruchterman-Reingold style,
deterministic seed) and serves a standalone interactive viewer page
(no build step, no npm — a single self-contained HTML with canvas).

Endpoints:
  - layout(case_id, w, h) -> nodes with x/y, links, clusters by type
  - viewer(case_id)       -> HTML page that fetches layout() and lets the
                             analyst drag nodes, zoom, hover for meta

Layout notes: capped at 400 nodes for readability (degree-ordered cutoff —
keeps the best-connected core); large graphs get paged via `top` param.

Lawful-use note: renders only data already in the case store.
"""
import json
import math
import random

import db

SCHEMA = ""  # uses cases entities/edges tables — no new tables needed


def graph_data(case_id, top=400):
    """Nodes + links for a case, degree-ordered, capped at `top` nodes."""
    c = db.get_db()
    ents = c.execute(
        "SELECT id,type,value,meta FROM entities WHERE case_id=? ORDER BY id",
        (case_id,)).fetchall()
    links_all = c.execute(
        "SELECT src_id,dst_id,relation,weight FROM edges WHERE case_id=?",
        (case_id,)).fetchall()
    degree = {}
    for l in links_all:
        degree[l["src_id"]] = degree.get(l["src_id"], 0) + 1
        degree[l["dst_id"]] = degree.get(l["dst_id"], 0) + 1
    ordered = sorted(ents, key=lambda e: -degree.get(e["id"], 0))
    keep = {e["id"] for e in ordered[:int(top)]}
    nodes = []
    for e in ordered[:int(top)]:
        try:
            meta = json.loads(e["meta"] or "{}")
        except ValueError:
            meta = {}
        nodes.append({"id": e["id"], "label": e["value"][:60],
                      "type": e["type"], "degree": degree.get(e["id"], 0),
                      "source": meta.get("source")})
    links = [{"src": l["src_id"], "dst": l["dst_id"],
              "relation": l["relation"], "weight": l["weight"]}
             for l in links_all if l["src_id"] in keep and l["dst_id"] in keep]
    return nodes, links


def _layout(nodes, links, width=1200, height=800, iterations=150, seed=42):
    """Fruchterman-Reingold (spring) layout, deterministic via fixed seed."""
    rng = random.Random(seed)
    n = len(nodes)
    if n == 0:
        return []
    idx = {node["id"]: i for i, node in enumerate(nodes)}
    pos = [[rng.uniform(0, width), rng.uniform(0, height)] for _ in range(n)]
    deg = [0] * n
    adj = [[] for _ in range(n)]
    for l in links:
        a, b = idx.get(l["src"]), idx.get(l["dst"])
        if a is None or b is None or a == b:
            continue
        adj[a].append((b, l.get("weight") or 1.0))
        adj[b].append((a, l.get("weight") or 1.0))
        deg[a] += 1
        deg[b] += 1
    k = math.sqrt((width * height) / max(n, 1))  # ideal spacing
    temp = width / 8
    for it in range(iterations):
        disp = [[0.0, 0.0] for _ in range(n)]
        for i in range(n):
            for j in range(i + 1, n):
                dx = pos[i][0] - pos[j][0]
                dy = pos[i][1] - pos[j][1]
                d2 = dx * dx + dy * dy or 0.01
                d = math.sqrt(d2)
                force = (k * k) / d2  # repulsion
                disp[i][0] += force * dx / d
                disp[i][1] += force * dy / d
                disp[j][0] -= force * dx / d
                disp[j][1] -= force * dy / d
        for i in range(n):
            for (j, w) in adj[i]:
                dx = pos[i][0] - pos[j][0]
                dy = pos[i][1] - pos[j][1]
                d = math.sqrt(dx * dx + dy * dy) or 0.01
                force = (d * d) / k * w  # attraction
                disp[i][0] -= force * dx / d
                disp[i][1] -= force * dy / d
        for i in range(n):
            dx, dy = disp[i]
            d = math.sqrt(dx * dx + dy * dy) or 0.01
            step = min(d, temp)
            pos[i][0] += dx / d * step
            pos[i][1] += dy / d * step
            pos[i][0] = max(20.0, min(width - 20.0, pos[i][0]))
            pos[i][1] = max(20.0, min(height - 20.0, pos[i][1]))
        temp *= 0.95
    return pos


TYPE_COLORS = {
    "person": "#4da3ff", "email": "#ffb84d", "domain": "#7bd88f",
    "ip": "#ff7b7b", "phone": "#c792ea", "username": "#f78c6c",
    "handle": "#f78c6c", "company": "#82aaff", "geo": "#ffcb6b",
}


def layout(case_id, width=1200, height=800, top=400, seed=42):
    """Compute layout: nodes carry x/y + type color; links reference ids."""
    try:
        nodes, links = graph_data(case_id, top=top)
        if not nodes:
            return {"status": "ok", "case_id": case_id, "nodes": [], "links": [],
                    "note": "no entities yet — run recon/deep search with case_id"}
        pos = _layout(nodes, links, int(width), int(height), seed=int(seed))
        by_id = {node["id"]: node for node in nodes}
        for i, node in enumerate(nodes):
            node["x"] = round(pos[i][0], 1)
            node["y"] = round(pos[i][1], 1)
            node["color"] = TYPE_COLORS.get(node["type"], "#aaaaaa")
        types = sorted({node["type"] for node in nodes})
        return {"status": "ok", "case_id": case_id,
                "nodes": nodes, "links": links,
                "counts": {t: sum(1 for node in nodes if node["type"] == t)
                           for t in types},
                "truncated": len(nodes) >= int(top),
                "seed": int(seed)}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}


VIEWER_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>Xaxglog Graph Studio — case __CID__</title>
<style>
 body{margin:0;background:#0d1117;color:#c9d1d9;font:13px/1.4 ui-sans-serif,system-ui}
 #bar{padding:8px 12px;background:#161b22;border-bottom:1px solid #30363d;display:flex;gap:14px;align-items:center}
 #cv{display:block;cursor:grab}
 .chip{padding:2px 8px;border-radius:10px;background:#21262d}
 #info{position:fixed;padding:6px 10px;background:#161b22;border:1px solid #30363d;border-radius:6px;display:none;pointer-events:none;max-width:320px}
</style></head><body>
<div id="bar"><b>Graph Studio</b> <span id="cnt"></span><span id="leg"></span>
 <span style="margin-left:auto">drag to move · wheel to zoom · hover for detail</span></div>
<canvas id="cv" width="1600" height="900"></canvas><div id="info"></div>
<script>
const CID="__CID__"; const API="__API__";
const cv=document.getElementById("cv"), ctx=cv.getContext("2d"), info=document.getElementById("info");
let G=null, cam={x:0,y:0,s:1}, drag=null, hover=null;
fetch(API+"/api/graph/"+CID+"/layout").then(r=>r.json()).then(g=>{
  if(g.status!=="ok"){document.getElementById("cnt").textContent=g.error||"error";return;}
  G=g; document.getElementById("cnt").textContent=
    g.nodes.length+" nodes, "+g.links.length+" links"+(g.truncated?" (truncated)":"");
  const counts=Object.entries(g.counts||{});
  document.getElementById("leg").innerHTML=counts.map(([t,n])=>
    '<span class="chip" style="border:1px solid '+(g.nodes.find(n2=>n2.type===t)||{}).color+
    '">'+t+' '+n+'</span>').join(" ");
  const xs=g.nodes.map(n=>n.x), ys=g.nodes.map(n=>n.y);
  cam.x=(Math.min(...xs)+Math.max(...xs))/2; cam.y=(Math.min(...ys)+Math.max(...ys))/2;
  cam.s=Math.min(cv.width/(Math.max(...xs)-Math.min(...xs)+120),
                 cv.height/(Math.max(...ys)-Math.min(...ys)+120));
  draw();
});
function T(n){return {x:(n.x-cam.x)*cam.s+cv.width/2, y:(n.y-cam.y)*cam.s+cv.height/2};}
function draw(){
  if(!G)return; ctx.clearRect(0,0,cv.width,cv.height); ctx.lineWidth=1;
  for(const l of G.links){
    const a=G.nodes.find(n=>n.id===l.src), b=G.nodes.find(n=>n.id===l.dst);
    if(!a||!b)continue; const pa=T(a), pb=T(b);
    ctx.strokeStyle="rgba(110,118,129,"+(0.22+0.12*(l.weight||1))+")";
    ctx.beginPath(); ctx.moveTo(pa.x,pa.y); ctx.lineTo(pb.x,pb.y); ctx.stroke();
  }
  hover=null;
  const mx=event&&event.x, my=event&&event.y;
  for(const n of G.nodes){
    const p=T(n), r=Math.max(4, Math.min(16, 4+n.degree*1.5));
    ctx.fillStyle=n.color;
    ctx.beginPath(); ctx.arc(p.x,p.y,r,0,7); ctx.fill();
    if(mx!==undefined && (p.x-mx)**2+(p.y-my)**2 < r*r+4) hover={n,p};
    if(cam.s>0.55 || n.degree>2){
      ctx.fillStyle="rgba(201,209,217,.85)"; ctx.font="11px sans-serif";
      ctx.fillText(n.label.slice(0,34), p.x+r+4, p.y+4);
    }
  }
  if(hover){
    info.style.display="block";
    info.style.left=(event.x+14)+"px"; info.style.top=(event.y+14)+"px";
    info.innerHTML="<b>"+hover.n.label+"</b><br>type: "+hover.n.type+
      "<br>degree: "+hover.n.degree+(hover.n.source?"<br>source: "+hover.n.source:"");
    cv.style.cursor="pointer";
  }else{info.style.display="none"; cv.style.cursor=drag?"grabbing":"grab";}
}
let event=null;
cv.addEventListener("mousemove",e=>{
  event={x:e.offsetX,y:e.offsetY};
  if(drag&&G){drag.n.x+=(e.movementX/cam.s); drag.n.y+=(e.movementY/cam.s);}
  draw();
});
cv.addEventListener("mousedown",e=>{if(hover)drag={n:hover.n};});
addEventListener("mouseup",()=>{drag=null;});
cv.addEventListener("wheel",e=>{e.preventDefault();
  const f=e.deltaY<0?1.12:0.89; cam.s=Math.max(0.05,Math.min(6,cam.s*f)); draw();},{passive:false});
</script></body></html>"""


def viewer_html(case_id):
    """Self-contained viewer page for one case's graph."""
    import os
    api = os.getenv("REACT_APP_API") or f"http://{os.getenv('HOST', '127.0.0.1')}:{os.getenv('PORT', '5000')}"
    if api.endswith("/api"):
        api = api[:-4]
    return (VIEWER_HTML.replace("__CID__", str(int(case_id)))
            .replace("__API__", api.rstrip("/")))
