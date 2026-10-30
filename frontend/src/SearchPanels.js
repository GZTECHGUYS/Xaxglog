import React, { useEffect, useMemo, useState } from 'react';

import { S as CYBER_S } from './cyberTheme';

// Legacy values are kept for any panel-specific keys; CYBERDECK theme
// values win for every shared key.
const LEGACY_S = {
  section: { background:'#161b22', border:'1px solid #30363d', borderRadius:8, padding:20, marginBottom:20 },
  title:   { margin:'0 0 4px', fontSize:16, color:'#e6edf3' },
  sub:     { margin:'0 0 14px', fontSize:12, color:'#8b949e', lineHeight:1.55 },
  input:   { background:'#0d1117', border:'1px solid #30363d', color:'#e6edf3', borderRadius:6,
             padding:'9px 12px', fontSize:13, outline:'none', width:'100%' },
  btn:     { background:'#1f6feb', color:'#fff', border:'none', borderRadius:6, padding:'9px 16px',
             fontSize:13, cursor:'pointer', fontWeight:600, whiteSpace:'nowrap' },
  ghost:   { background:'#21262d', color:'#e6edf3', border:'1px solid #30363d', borderRadius:6,
             padding:'9px 14px', fontSize:13, cursor:'pointer', whiteSpace:'nowrap' },
  row:     { display:'flex', gap:8, flexWrap:'wrap', alignItems:'center' },
  pill:    { color:'#fff', padding:'2px 9px', borderRadius:12, fontSize:11, fontWeight:600 },
  tag:     { background:'#21262d', color:'#8b949e', padding:'2px 7px', borderRadius:4, fontSize:11, marginRight:4 },
  card:    { background:'#0d1117', border:'1px solid #30363d', borderRadius:8, padding:'14px 16px', marginBottom:10 },
  mono:    { fontFamily:'ui-monospace,Menlo,monospace', fontSize:12, wordBreak:'break-all' },
  label:   { fontSize:11, color:'#8b949e', display:'block', marginBottom:4, textTransform:'uppercase', letterSpacing:'0.04em' },
  table:   { width:'100%', borderCollapse:'collapse', fontSize:12 },
  th:      { background:'#161b22', padding:'8px 10px', textAlign:'left', color:'#8b949e', fontWeight:600, borderBottom:'1px solid #30363d' },
  td:      { padding:'8px 10px', borderBottom:'1px solid #21262d', color:'#e6edf3', verticalAlign:'top' },
  select:  { background:'#0d1117', border:'1px solid #30363d', color:'#e6edf3', borderRadius:6, padding:'9px 10px', fontSize:13 },
  stats:   { display:'flex', gap:10, flexWrap:'wrap', margin:'12px 0' },
  stat:    { background:'#0d1117', border:'1px solid #30363d', borderRadius:8, padding:'10px 14px', minWidth:96 },
  num:     { display:'block', fontSize:20, fontWeight:700, color:'#e6edf3' },
  statL:   { fontSize:10, color:'#8b949e', textTransform:'uppercase', letterSpacing:'0.05em' },

};
const S = { ...LEGACY_S, ...CYBER_S };

const Err = ({ e }) => e ? (
  <div style={{ ...S.card, border:'1px solid #e74c3c', background:'#2a1a1a', color:'#e74c3c', fontSize:13 }}>
    {typeof e === 'string' ? e : JSON.stringify(e)}
  </div>) : null;

const Stats = ({ items }) => (
  <div style={S.stats}>{items.map(([l, v]) => (
    <div key={l} style={S.stat}><span style={S.num}>{v ?? 0}</span><span style={S.statL}>{l}</span></div>
  ))}</div>
);

const statusColour = (status) => ({
  verified:'#2ecc71', fragile:'#f1c40f', adapter:'#58a6ff', candidate:'#8b949e',
  optional_key:'#e67e22', link_out:'#9b59b6', blocked:'#e74c3c', error:'#e74c3c',
  unstable:'#e67e22',
}[status] || '#8b949e');

function collectRows(node, out = [], depth = 0) {
  if (!node || depth > 5 || out.length > 500) return out;
  if (Array.isArray(node)) {
    node.forEach(x => collectRows(x, out, depth + 1));
    return out;
  }
  if (typeof node !== 'object') return out;
  if (node.url || node.title || node.name || node.display_name || node.login) {
    out.push(node);
    return out;
  }
  for (const [k, v] of Object.entries(node)) {
    if (['status', 'error', 'note', 'disclaimer', 'input'].includes(k)) continue;
    if (v && typeof v === 'object') collectRows(v, out, depth + 1);
  }
  return out;
}

const relatizeTime = (ts) => {
  if (!ts) return '';
  const d = new Date(ts);
  if (isNaN(d.getTime())) return String(ts).slice(0, 19);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60) return 'just now';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  if (diff < 2592000) return Math.floor(diff / 86400) + 'd ago';
  return d.toISOString().slice(0, 10);
};

const platColour = (name) =>
  `hsl(${[...(name || '')].reduce((a, c) => (a * 31 + c.charCodeAt(0)) % 360, 7)}, 55%, 40%)`;

const confColour = (c) => ({
  high:'#2ecc71', medium:'#1f6feb', low:'#9b59b6', lead:'#8b949e',
})[String(c || '').toLowerCase()] || null;

function MatchBadge({ row }) {
  const m = typeof row.match === 'number' ? row.match : null;
  if (m == null && !row.confidence) return null;
  const c = confColour(row.confidence);
  const label = m != null ? `match ${(m * 100).toFixed(0)}%` : row.confidence;
  return <span style={{ ...S.pill, background: c || '#30363d', fontSize:10 }}>{label}</span>;
}

function ResultTable({ rows, empty }) {
  if (!rows.length) {
    return <div style={{ ...S.card, color:'#8b949e', fontSize:13 }}>{empty || 'No automatic result for this group.'}</div>;
  }
  return (
    <div style={{ ...S.card, overflowX:'auto' }}>
      <table style={S.table}>
        <thead><tr>
          <th style={S.th}>Source</th><th style={S.th}>Title / name</th>
          <th style={S.th}>Detail</th><th style={S.th}>Meta</th><th style={S.th}>URL</th>
        </tr></thead>
        <tbody>
          {rows.slice(0, 250).map((r, i) => {
            const src = r.source_label || r.source || r.platform || 'source';
            const handle = r.handle || r.acct || '';
            const when = r.published || r.seen || r.last_paper || r.created_at || '';
            return (
              <tr key={i}>
                <td style={S.td}>
                  <span style={{ ...S.pill, background: r.platform ? platColour(r.platform) : statusColour(r.fragile ? 'fragile' : (r.verified ? 'verified' : 'candidate')) }}>
                    {r.platform || src}
                  </span>
                  {r.platform && r.source && r.source !== r.platform &&
                    <div style={{ color:'#8b949e', fontSize:10, marginTop:4 }}>{r.source}</div>}
                </td>
                <td style={S.td}>
                  <strong style={{ lineHeight:1.35 }}>{r.title || r.name || r.display_name || r.login || '—'}</strong>
                  {(r.author || handle) && <div style={{ ...S.tag, marginTop:4 }}>@{String(r.author || handle).replace(/^@/, '')}</div>}
                  <MatchBadge row={r} />
                </td>
                <td style={{ ...S.td, maxWidth:340 }}>
                  {(r.snippet || r.detail || r.description || r.bio || '').slice(0, 220)}
                </td>
                <td style={{ ...S.td, whiteSpace:'nowrap', color:'#8b949e', fontSize:11 }}>
                  {when && <div>🕒 {relatizeTime(when)}</div>}
                  {r.location && <div>📍 {String(r.location).slice(0, 40)}</div>}
                  {r.reputation != null && <div>rep {r.reputation}</div>}
                  {r.followers != null && <div>{r.followers} followers</div>}
                  {r.institutions && <div style={{ maxWidth:120 }}>{String(r.institutions).slice(0, 40)}</div>}
                  {r.rating != null && <div>score {r.rating}</div>}
                </td>
                <td style={S.td}>{r.url ? <a href={r.url} target="_blank" rel="noopener noreferrer"
                  style={{ ...S.mono, color:'#58a6ff' }}>{String(r.url).replace(/^https?:\/\//, '').slice(0, 60)}</a> : ''}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------- Deep search
export function DeepSearchPanel({ api }) {
  const [query, setQuery] = useState('');
  const [busy, setBusy] = useState('');
  const [res, setRes] = useState(null);
  const [identity, setIdentity] = useState(null);
  const [modules, setModules] = useState(null);
  const [links, setLinks] = useState([]);
  const [err, setErr] = useState('');

  const runDeep = async () => {
    if (!query.trim()) return;
    setBusy('deep'); setErr(''); setRes(null); setIdentity(null); setModules(null);
    try {
      const r = await api.post('/deep/search', { query: query.trim() }, { timeout: 180000 });
      setRes(r.data);
    } catch (e) { setErr(e.response?.data?.error || e.message); }
    setBusy('');
  };

  const runIdentity = async () => {
    if (!query.trim()) return;
    setBusy('identity'); setErr(''); setRes(null); setIdentity(null); setModules(null);
    try {
      const r = await api.post('/identity/search', {
        query: query.trim(), depth: 'standard', include_social: true,
        include_web: true, include_records: true, include_code: false,
        include_link_out: true,
      }, { timeout: 300000 });
      setIdentity(r.data);
    } catch (e) { setErr(e.response?.data?.error || e.message); }
    setBusy('');
  };

  const runModules = async () => {
    if (!query.trim()) return;
    setBusy('modules'); setErr(''); setRes(null); setIdentity(null); setModules(null);
    try {
      const r = await api.post('/module-registry/search', { query: query.trim(), limit: 60 }, { timeout: 180000 });
      setModules(r.data);
    } catch (e) { setErr(e.response?.data?.error || e.message); }
    setBusy('');
  };

  const buildLinks = async () => {
    if (!query.trim()) return;
    setBusy('links'); setErr('');
    try {
      const r = await api.get('/sources/links', { params: { q: query.trim(), limit: 250 } });
      setLinks(r.data.links || []);
    } catch (e) { setErr(e.response?.data?.error || e.message); }
    setBusy('');
  };

  const deepGroups = res?.results && typeof res.results === 'object' ? Object.entries(res.results) : [];
  const idRows = identity?.results || [];
  const modRows = modules?.results || [];
  const modCov = modules?.coverage || {};

  return (
    <div style={S.section}>
      <h2 style={S.title}>Unified public-source search</h2>
      <p style={S.sub}>
        One query routes to the right engine: email, IP, domain, phone, company, person/handle.
        Automatic results only come from live-verified sources. Public-page scrapes are marked
        fragile; blocked, optional-key, unverified and link-out sources stay catalog-only.
      </p>
      <div style={S.row}>
        <input style={{ ...S.input, flex:2, minWidth:260 }} value={query}
          placeholder="8.8.8.8 / example.com / jane@example.com / Jane Doe / jane_doe"
          onChange={e => setQuery(e.target.value)} onKeyDown={e => e.key === 'Enter' && runDeep()} />
        <button style={S.btn} onClick={runDeep} disabled={!!busy}>{busy === 'deep' ? 'Searching…' : 'Auto deep search'}</button>
        <button style={S.ghost} onClick={runIdentity} disabled={!!busy}>{busy === 'identity' ? 'Running…' : 'Identity depth'}</button>
        <button style={S.ghost} onClick={runModules} disabled={!!busy}>{busy === 'modules' ? 'Running…' : 'Verified modules'}</button>
        <button style={S.ghost} onClick={buildLinks} disabled={!!busy}>{busy === 'links' ? 'Building…' : 'Link-outs'}</button>
      </div>
      <Err e={err} />

      {res && (
        <>
          <Stats items={[
            ['detected type', res.detected_type || 'unknown'],
            ['result groups', deepGroups.length],
            ['disclaimer', res.disclaimer ? 'shown' : 'n/a'],
          ]} />
          <div style={{ ...S.card, color:'#8b949e', fontSize:12 }}>{res.disclaimer}</div>
          {deepGroups.map(([group, value]) => {
            const rows = collectRows(value);
            return (
              <div key={group}>
                <div style={{ ...S.label, marginTop:14 }}>{group} · {rows.length} row{rows.length === 1 ? '' : 's'}</div>
                <ResultTable rows={rows} empty={`${group} returned no parsed rows. Raw response is shown below.`} />
                {!rows.length && (
                  <details style={S.card}>
                    <summary style={{ cursor:'pointer', color:'#58a6ff' }}>raw {group}</summary>
                    <pre style={{ ...S.mono, whiteSpace:'pre-wrap', maxHeight:360, overflow:'auto' }}>{JSON.stringify(value, null, 2)}</pre>
                  </details>
                )}
              </div>
            );
          })}
          <details style={{ ...S.card, marginTop:12 }}>
            <summary style={{ cursor:'pointer', color:'#58a6ff' }}>raw deep-search response</summary>
            <pre style={{ ...S.mono, whiteSpace:'pre-wrap', maxHeight:520, overflow:'auto' }}>{JSON.stringify(res, null, 2)}</pre>
          </details>
        </>
      )}

      {identity && (
        <>
          <Stats items={[
            ['total leads', identity.total], ['high', identity.by_confidence?.high],
            ['medium', identity.by_confidence?.medium], ['lead', identity.by_confidence?.lead],
            ['sources planned', identity.coverage?.planned], ['executed', identity.coverage?.executed],
            ['blocked', identity.coverage?.blocked], ['link-outs', (identity.link_out || []).length],
          ]} />
          <div style={S.card}>
            <div style={S.label}>coverage diagnostics</div>
            <p style={{ ...S.sub, marginBottom:8 }}>
              {identity.coverage?.planned} planned · {identity.coverage?.executed} executed
              ({identity.coverage?.coverage_pct}%) · {identity.coverage?.ok} returned leads ·
              {' '}{identity.coverage?.empty} empty · {identity.coverage?.blocked} blocked ·
              {' '}{identity.coverage?.skipped_key} optional-key · {identity.coverage?.link_out} link-out ·
              {' '}{identity.coverage?.not_checked} not checked
            </p>
            <div style={S.row}>
              {Object.values(identity.coverage?.by_source || {}).reduce((a, x) => {
                a[x.status] = (a[x.status] || 0) + 1; return a;
              }, {}) && Object.entries(Object.values(identity.coverage?.by_source || {}).reduce((a, x) => {
                a[x.status] = (a[x.status] || 0) + 1; return a;
              }, {})).map(([k, v]) => <span key={k} style={S.tag}>{k}: {v}</span>)}
            </div>
          </div>
          <ResultTable rows={idRows} empty="No automatic identity lead. Check coverage; blocked, link-out and optional-key sources are not counted." />
          {(identity.link_out || []).length > 0 && (
            <div style={S.card}>
              <div style={S.label}>public link-outs ({identity.link_out.length})</div>
              <div style={S.row}>{identity.link_out.slice(0, 300).map((x, i) => (
                <a key={i} href={x.url} target="_blank" rel="noopener noreferrer"
                  style={{ ...S.tag, color:'#58a6ff', textDecoration:'none' }}
                  title={`${x.category} · ${x.access} · ${x.status}`}>{x.label}</a>
              ))}</div>
            </div>
          )}
        </>
      )}

      {modules && (
        <>
          <Stats items={[
            ['results', modules.count], ['detected type', modules.detected_type || 'unknown'],
            ['planned', modCov.planned], ['executed', modCov.executed],
            ['ok', modCov.ok], ['empty', modCov.empty], ['blocked', modCov.blocked],
            ['errors', modCov.error], ['elapsed ms', modules.elapsed_ms],
          ]} />
          <div style={S.card}>
            <div style={S.label}>why this result set</div>
            <p style={{ ...S.sub, marginBottom:8 }}>{modules.diagnostics?.reason || modules.note}</p>
            <div style={S.row}>
              {(modules.diagnostics?.blocked || []).slice(0, 20).map(x => <span key={x} style={{ ...S.tag, color:'#e74c3c' }}>blocked · {x}</span>)}
              {(modules.diagnostics?.error || []).slice(0, 20).map(x => <span key={x} style={{ ...S.tag, color:'#e74c3c' }}>error · {x}</span>)}
              {(modules.diagnostics?.empty || []).slice(0, 20).map(x => <span key={x} style={S.tag}>empty · {x}</span>)}
            </div>
          </div>
          <ResultTable rows={modRows} empty="No verified module returned a usable row. Try Identity depth or build link-outs." />
          <details style={S.card}>
            <summary style={{ cursor:'pointer', color:'#58a6ff' }}>per-source coverage</summary>
            <pre style={{ ...S.mono, whiteSpace:'pre-wrap', maxHeight:360, overflow:'auto' }}>{JSON.stringify(modCov.by_source || {}, null, 2)}</pre>
          </details>
        </>
      )}

      {links.length > 0 && (
        <div style={{ ...S.card, marginTop:12 }}>
          <div style={S.label}>public link-outs ({links.length})</div>
          <div style={S.row}>{links.slice(0, 400).map((x, i) => (
            <a key={i} href={x.url} target="_blank" rel="noopener noreferrer"
              style={{ ...S.tag, color:'#58a6ff', textDecoration:'none' }}
              title={`${x.category} · ${x.access} · ${x.status}`}>{x.label}</a>
          ))}</div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- Module registry
export function ModuleRegistryPanel({ api }) {
  const [summary, setSummary] = useState(null);
  const [mods, setMods] = useState([]);
  const [filters, setFilters] = useState({ q:'', category:'', status:'', probe_type:'', region:'' });
  const [selected, setSelected] = useState([]);
  const [query, setQuery] = useState('');
  const [search, setSearch] = useState(null);
  const [verify, setVerify] = useState(null);
  const [links, setLinks] = useState([]);
  const [busy, setBusy] = useState('');
  const [err, setErr] = useState('');

  const load = async () => {
    setBusy('load'); setErr('');
    try {
      const [s, m] = await Promise.all([
        api.get('/module-registry/summary'),
        api.get('/module-registry/modules', { params: { ...filters, limit: 1000 } }),
      ]);
      setSummary(s.data);
      setMods(m.data.modules || []);
    } catch (e) { setErr(e.response?.data?.error || e.message); }
    setBusy('');
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { load(); }, []);

  const categories = useMemo(() => Object.keys(summary?.by_category || {}).sort(), [summary]);
  const probeTypes = useMemo(() => Object.keys(summary?.by_probe || {}).sort(), [summary]);
  const statuses = useMemo(() => Object.keys(summary?.by_status || {}).sort(), [summary]);

  const toggle = (id) => setSelected(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
  const allVisible = mods.length > 0 && mods.every(m => selected.includes(m.id));
  const toggleAll = () => setSelected(allVisible ? [] : mods.map(m => m.id));

  const runSearch = async () => {
    if (!query.trim()) return;
    setBusy('search'); setErr(''); setSearch(null);
    try {
      const body = { query: query.trim(), limit: 60 };
      if (selected.length) body.ids = selected;
      const r = await api.post('/module-registry/search', body, { timeout: 180000 });
      setSearch(r.data);
    } catch (e) { setErr(e.response?.data?.error || e.message); }
    setBusy('');
  };

  const runVerify = async () => {
    if (!selected.length) { setErr('Select at least one module to verify.'); return; }
    setBusy('verify'); setErr(''); setVerify(null);
    try {
      const r = await api.post('/module-registry/verify', {
        ids: selected, query: query.trim() || 'John Smith', checks: 2, persist: true,
      }, { timeout: 300000 });
      setVerify(r.data);
      await load();
    } catch (e) { setErr(e.response?.data?.error || e.message); }
    setBusy('');
  };

  const buildLinks = async () => {
    if (!query.trim()) return;
    setBusy('links'); setErr('');
    try {
      const r = await api.post('/module-registry/links', { query: query.trim(), limit: 250 });
      setLinks(r.data.links || []);
    } catch (e) { setErr(e.response?.data?.error || e.message); }
    setBusy('');
  };

  return (
    <div style={S.section}>
      <h2 style={S.title}>Declarative module registry</h2>
      <p style={S.sub}>
        One declaration per public source with a generic probe recipe. The registry reports what is
        actually verified: JSON APIs, public profile pages (fragile), search pages (fragile), oEmbed,
        existing adapters and link-outs. It does not pad counts with blocked or unverified sources.
      </p>
      <Err e={err} />
      {summary && (
        <>
          <Stats items={[
            ['declared', summary.total], ['verified', summary.verified], ['fragile', summary.fragile],
            ['automatic', summary.automatic], ['adapter', summary.adapter], ['candidate', summary.candidate],
            ['optional key', summary.optional_key], ['link-out', summary.link_out],
            ['blocked', summary.blocked], ['error', summary.error],
          ]} />
          <div style={S.card}>
            <div style={S.label}>honest status rule</div>
            <p style={{ ...S.sub, marginBottom:8 }}>{summary.note}</p>
            <div style={S.row}>
              {Object.entries(summary.by_probe || {}).map(([k, v]) => <span key={k} style={S.tag}>{k}: {v}</span>)}
            </div>
          </div>
        </>
      )}

      <div style={S.row}>
        <input style={{ ...S.input, flex:2, minWidth:220 }} value={filters.q}
          placeholder="filter id / label / adapter"
          onChange={e => setFilters({ ...filters, q: e.target.value })} />
        <select style={S.select} value={filters.category}
          onChange={e => setFilters({ ...filters, category: e.target.value })}>
          <option value="">all categories</option>
          {categories.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <select style={S.select} value={filters.status}
          onChange={e => setFilters({ ...filters, status: e.target.value })}>
          <option value="">all statuses</option>
          {statuses.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <select style={S.select} value={filters.probe_type}
          onChange={e => setFilters({ ...filters, probe_type: e.target.value })}>
          <option value="">all probes</option>
          {probeTypes.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <button style={S.ghost} onClick={load} disabled={!!busy}>{busy === 'load' ? 'Loading…' : 'Reload'}</button>
      </div>
      <div style={{ ...S.row, marginTop:8 }}>
        <input style={{ ...S.input, flex:2, minWidth:240 }} value={query}
          placeholder="search query for selected/verified modules"
          onChange={e => setQuery(e.target.value)} onKeyDown={e => e.key === 'Enter' && runSearch()} />
        <button style={S.btn} onClick={runSearch} disabled={!!busy}>{busy === 'search' ? 'Searching…' : 'Run verified search'}</button>
        <button style={S.ghost} onClick={runVerify} disabled={!!busy || !selected.length}>{busy === 'verify' ? 'Verifying…' : `Verify selected (${selected.length})`}</button>
        <button style={S.ghost} onClick={buildLinks} disabled={!!busy}>{busy === 'links' ? 'Building…' : 'Build link-outs'}</button>
      </div>

      {search && (
        <>
          <Stats items={[
            ['results', search.count], ['planned', search.coverage?.planned],
            ['executed', search.coverage?.executed], ['ok', search.coverage?.ok],
            ['empty', search.coverage?.empty], ['blocked', search.coverage?.blocked],
            ['errors', search.coverage?.error], ['elapsed ms', search.elapsed_ms],
          ]} />
          <div style={S.card}>
            <div style={S.label}>why this result set</div>
            <p style={{ ...S.sub, marginBottom:8 }}>{search.diagnostics?.reason || search.note}</p>
            <div style={S.row}>
              {(search.diagnostics?.blocked || []).map(x => <span key={x} style={{ ...S.tag, color:'#e74c3c' }}>blocked · {x}</span>)}
              {(search.diagnostics?.error || []).map(x => <span key={x} style={{ ...S.tag, color:'#e74c3c' }}>error · {x}</span>)}
              {(search.diagnostics?.empty || []).slice(0, 30).map(x => <span key={x} style={S.tag}>empty · {x}</span>)}
            </div>
          </div>
          <ResultTable rows={search.results || []} empty="No automatic result from the selected/verified modules." />
        </>
      )}

      {verify && (
        <div style={S.card}>
          <div style={S.label}>verification result</div>
          <Stats items={[
            ['checked', verify.checked], ['verified', verify.verified], ['fragile', verify.fragile],
            ['blocked', verify.blocked], ['error', verify.error], ['empty', verify.empty],
            ['unstable', verify.unstable],
          ]} />
          <pre style={{ ...S.mono, whiteSpace:'pre-wrap', maxHeight:320, overflow:'auto' }}>{JSON.stringify(verify.results, null, 2)}</pre>
        </div>
      )}

      {links.length > 0 && (
        <div style={S.card}>
          <div style={S.label}>module link-outs ({links.length})</div>
          <div style={S.row}>{links.slice(0, 400).map((x, i) => (
            <a key={i} href={x.url} target="_blank" rel="noopener noreferrer"
              style={{ ...S.tag, color:'#58a6ff', textDecoration:'none' }}
              title={`${x.category} · ${x.access} · ${x.status}`}>{x.label}</a>
          ))}</div>
        </div>
      )}

      <div style={{ ...S.card, marginTop:12, overflowX:'auto' }}>
        <div style={{ ...S.row, justifyContent:'space-between', marginBottom:8 }}>
          <div style={S.label}>modules ({mods.length})</div>
          <button style={S.ghost} onClick={toggleAll}>{allVisible ? 'Clear selection' : 'Select visible'}</button>
        </div>
        <table style={S.table}>
          <thead><tr>
            <th style={S.th}>Select</th><th style={S.th}>Module</th><th style={S.th}>Category</th>
            <th style={S.th}>Access</th><th style={S.th}>Status</th><th style={S.th}>Probe</th>
            <th style={S.th}>Region</th><th style={S.th}>Key</th>
          </tr></thead>
          <tbody>
            {mods.slice(0, 1000).map(m => (
              <tr key={m.id}>
                <td style={S.td}><input type="checkbox" checked={selected.includes(m.id)} onChange={() => toggle(m.id)} /></td>
                <td style={S.td}><strong>{m.label}</strong><div style={S.mono}>{m.id}</div></td>
                <td style={S.td}>{m.category}</td>
                <td style={S.td}>{m.access}</td>
                <td style={S.td}><span style={{ ...S.pill, background: statusColour(m.status) }}>{m.status}</span></td>
                <td style={S.td}>{m.probe_type}{m.fragile ? ' · fragile' : ''}</td>
                <td style={S.td}>{m.region}</td>
                <td style={S.td}>{m.requires_key ? (m.key_env || 'required') : '—'}</td>
              </tr>
            ))}
            {!mods.length && <tr><td colSpan={8} style={{ ...S.td, color:'#8b949e' }}>No modules match the filters.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
