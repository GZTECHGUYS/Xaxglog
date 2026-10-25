import React, { useEffect, useMemo, useState } from 'react';

const S = {
  section: { background:'#161b22', border:'1px solid #30363d', borderRadius:8, padding:20, marginBottom:20 },
  title:   { margin:'0 0 4px', fontSize:16, color:'#e6edf3' },
  sub:     { margin:'0 0 14px', fontSize:12, color:'#8b949e' },
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

const Err = ({ e }) => e ? (
  <div style={{ ...S.card, border:'1px solid #e74c3c', background:'#2a1a1a', color:'#e74c3c', fontSize:13 }}>
    {typeof e === 'string' ? e : JSON.stringify(e)}
  </div>) : null;

const Chips = ({ items }) => (
  <div style={S.row}>{(items || []).map((x, i) => <span key={i} style={S.tag}>{x}</span>)}</div>
);

const confidenceColour = (c) => ({ high:'#e74c3c', medium:'#e67e22', lead:'#8b949e' }[c] || '#8b949e');

function Stats({ items }) {
  return <div style={S.stats}>{items.map(([l, v]) => (
    <div key={l} style={S.stat}><span style={S.num}>{v ?? 0}</span><span style={S.statL}>{l}</span></div>
  ))}</div>;
}

// ---------------------------------------------------------------- Identity
export function IdentityPanel({ api }) {
  const [query, setQuery] = useState('');
  const [depth, setDepth] = useState('standard');
  const [country, setCountry] = useState('');
  const [social, setSocial] = useState(true);
  const [web, setWeb] = useState(true);
  const [records, setRecords] = useState(true);
  const [code, setCode] = useState(false);
  const [linksOn, setLinksOn] = useState(true);
  const [res, setRes] = useState(null);
  const [plan, setPlan] = useState(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const body = useMemo(() => ({
    query: query.trim(),
    depth,
    country: country.trim() || undefined,
    include_social: social,
    include_web: web,
    include_records: records,
    include_code: code,
    include_link_out: linksOn,
  }), [query, depth, country, social, web, records, code, linksOn]);

  const run = async () => {
    if (!body.query) return;
    setBusy(true); setErr(''); setRes(null);
    try {
      const r = await api.post('/identity/search', body, { timeout: 300000 });
      setRes(r.data);
    } catch (e) {
      setErr(e.response?.data?.error || e.message);
      setRes(e.response?.data || null);
    }
    setBusy(false);
  };

  const showPlan = async () => {
    if (!body.query) return;
    setBusy(true); setErr('');
    try {
      const r = await api.get('/identity/plan', { params: body });
      setPlan(r.data);
    } catch (e) { setErr(e.response?.data?.error || e.message); }
    setBusy(false);
  };

  const showVariants = async () => {
    if (!body.query) return;
    setBusy(true); setErr('');
    try {
      const r = await api.get('/identity/variants', { params: { q: body.query, limit: 60 } });
      setPlan(r.data);
    } catch (e) { setErr(e.response?.data?.error || e.message); }
    setBusy(false);
  };

  const cov = res?.coverage || {};
  const counts = res?.by_confidence || {};
  const rows = res?.results || [];
  const links = res?.link_out || [];
  const norm = res?.normalized || plan?.normalized || {};
  const variants = res?.variants || plan?.variants || [];
  const handles = res?.handle_variants || plan?.handle_variants || [];
  const groups = plan?.groups || {};

  return (
    <div style={S.section}>
      <h2 style={S.title}>Identity Intelligence</h2>
      <p style={S.sub}>
        Comma/suffix/initial normalization, always-on variants, extra keyless academic/archive/code
        indexes, public-record modules, a general web pass, dedupe, confidence and per-source
        coverage. Blocked, link-out and optional-key sources are never counted as automatic hits.
      </p>
      <div style={S.row}>
        <input style={{ ...S.input, flex:2, minWidth:260 }} value={query}
          placeholder="Doe, Jane A. Jr. / Jane Doe / jane_doe"
          onChange={e => setQuery(e.target.value)} onKeyDown={e => e.key === 'Enter' && run()} />
        <select style={S.select} value={depth} onChange={e => setDepth(e.target.value)}>
          <option value="quick">quick</option><option value="standard">standard</option><option value="deep">deep</option>
        </select>
        <input style={{ ...S.input, width:100 }} value={country} placeholder="country"
          onChange={e => setCountry(e.target.value)} />
        <button style={S.btn} onClick={run} disabled={busy}>{busy ? 'Searching…' : 'Run identity search'}</button>
        <button style={S.ghost} onClick={showPlan} disabled={busy}>Plan sources</button>
        <button style={S.ghost} onClick={showVariants} disabled={busy}>Variants</button>
      </div>
      <div style={{ ...S.row, marginTop:8 }}>
        <label style={{ color:'#8b949e', fontSize:12 }}><input type="checkbox" checked={social} onChange={e => setSocial(e.target.checked)} /> social</label>
        <label style={{ color:'#8b949e', fontSize:12 }}><input type="checkbox" checked={web} onChange={e => setWeb(e.target.checked)} /> web</label>
        <label style={{ color:'#8b949e', fontSize:12 }}><input type="checkbox" checked={records} onChange={e => setRecords(e.target.checked)} /> records</label>
        <label style={{ color:'#8b949e', fontSize:12 }}><input type="checkbox" checked={code} onChange={e => setCode(e.target.checked)} /> code</label>
        <label style={{ color:'#8b949e', fontSize:12 }}><input type="checkbox" checked={linksOn} onChange={e => setLinksOn(e.target.checked)} /> link-outs</label>
      </div>
      <Err e={err} />

      {res && (
        <>
          <Stats items={[
            ['total leads', res.total], ['high', counts.high], ['medium', counts.medium],
            ['lead', counts.lead], ['sources planned', cov.planned], ['executed', cov.executed],
            ['blocked', cov.blocked], ['link-outs', links.length],
          ]} />
          <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit,minmax(320px,1fr))', gap:12 }}>
            <div style={S.card}>
              <div style={S.label}>normalized & variants</div>
              <div style={{ color:'#e6edf3', fontSize:13, lineHeight:1.7 }}>
                <div><strong>input</strong> {norm.input || ''}</div>
                <div><strong>normalized</strong> {norm.normalized || norm.base || ''}</div>
                {norm.comma_form && <div><strong>comma form</strong> {norm.comma_form}</div>}
                {norm.suffixes?.length > 0 && <div><strong>suffixes</strong> {norm.suffixes.join(', ')}</div>}
                <div><strong>script</strong> {norm.script || ''}</div>
              </div>
              <div style={{ ...S.label, marginTop:12 }}>name variants</div>
              <Chips items={variants} />
              <div style={{ ...S.label, marginTop:12 }}>handle spellings</div>
              <Chips items={handles} />
            </div>
            <div style={S.card}>
              <div style={S.label}>coverage diagnostics</div>
              <p style={{ ...S.sub, marginBottom:8 }}>
                {cov.planned} planned · {cov.executed} executed ({cov.coverage_pct}%) · {cov.ok} returned leads ·
                {' '}{cov.empty} empty · {cov.blocked} blocked · {cov.skipped_key} optional-key ·
                {' '}{cov.link_out} link-out · {cov.not_checked} not checked
              </p>
              <Chips items={Object.entries(cov.by_source ? Object.values(cov.by_source).reduce((a, x) => {
                a[x.status] = (a[x.status] || 0) + 1; return a;
              }, {}) : {}).map(([k, v]) => `${k}: ${v}`)} />
              <details style={{ marginTop:10 }}>
                <summary style={{ cursor:'pointer', color:'#58a6ff', fontSize:12 }}>problem / unexecuted sources</summary>
                <div style={{ ...S.row, marginTop:8 }}>
                  {Object.values(cov.by_source || {}).filter(x => ['blocked', 'error', 'not_checked'].includes(x.status))
                    .slice(0, 60).map((x, i) => <span key={i} style={S.tag} title={x.detail || x.status}>{x.label} · {x.status}</span>)}
                </div>
              </details>
            </div>
          </div>

          <div style={{ ...S.card, marginTop:12, overflowX:'auto' }}>
            <div style={S.label}>merged leads ({rows.length})</div>
            <table style={S.table}>
              <thead><tr><th style={S.th}>Confidence</th><th style={S.th}>Source</th><th style={S.th}>Name</th><th style={S.th}>Detail</th><th style={S.th}>URL</th></tr></thead>
              <tbody>
                {rows.slice(0, 300).map((r, i) => (
                  <tr key={i}>
                    <td style={S.td}><span style={{ ...S.pill, background: confidenceColour(r.confidence) }}>{r.confidence || 'lead'}</span></td>
                    <td style={S.td}>{r.source}</td>
                    <td style={S.td}><strong>{r.name}</strong></td>
                    <td style={S.td}>{r.detail}</td>
                    <td style={S.td}>{r.url ? <a href={r.url} target="_blank" rel="noopener noreferrer" style={{ ...S.mono, color:'#58a6ff' }}>{r.url}</a> : ''}</td>
                  </tr>
                ))}
                {!rows.length && <tr><td colSpan={5} style={{ ...S.td, color:'#8b949e' }}>No automatic hit. Check coverage: blocked, link-out and optional-key sources were not counted.</td></tr>}
              </tbody>
            </table>
          </div>

          <div style={{ ...S.card, marginTop:12 }}>
            <div style={S.label}>public link-outs ({links.length})</div>
            <div style={S.row}>{links.slice(0, 300).map((x, i) => (
              <a key={i} href={x.url} target="_blank" rel="noopener noreferrer" style={{ ...S.tag, color:'#58a6ff', textDecoration:'none' }}
                title={`${x.category} · ${x.access} · ${x.status}`}>{x.label}</a>
            ))}</div>
          </div>

          <details style={{ ...S.card, marginTop:12 }}>
            <summary style={{ cursor:'pointer', color:'#58a6ff' }}>raw response</summary>
            <pre style={{ ...S.mono, whiteSpace:'pre-wrap', maxHeight:480, overflow:'auto' }}>{JSON.stringify(res, null, 2)}</pre>
          </details>
        </>
      )}

      {!res && plan && (
        <>
          <Stats items={[['kind', plan.kind], ['depth', plan.depth], ['planned sources', plan.source_plan?.count], ['variants', variants.length], ['categories', Object.keys(groups).length]]} />
          <div style={S.card}>
            <div style={S.label}>planned source groups</div>
            <div style={S.row}>{Object.entries(groups).sort().map(([k, v]) => <span key={k} style={S.tag}>{k} · {(v || []).length}</span>)}</div>
            <p style={{ ...S.sub, marginTop:10 }}>{plan.note}</p>
          </div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- Source registry
export function SourceRegistryPanel({ api }) {
  const [catalog, setCatalog] = useState(null);
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('');
  const [category, setCategory] = useState('');
  const [access, setAccess] = useState('');
  const [status, setStatus] = useState('');
  const [links, setLinks] = useState([]);
  const [verify, setVerify] = useState(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const load = async () => {
    setBusy(true); setErr('');
    try {
      const r = await api.get('/sources/registry', { params: { include_sources: true, limit: 1000 } });
      setCatalog(r.data);
    } catch (e) { setErr(e.response?.data?.error || e.message); }
    setBusy(false);
  };

  // Load once on mount; manual Reload uses the same function.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { load(); }, []);

  const rows = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return (catalog?.sources || []).filter(s => {
      if (category && s.category !== category) return false;
      if (access && s.access !== access) return false;
      if (status && s.status !== status) return false;
      if (!q) return true;
      return [s.id, s.label, s.adapter, s.region, s.note, ...(s.types || [])]
        .join(' ').toLowerCase().includes(q);
    });
  }, [catalog, filter, category, access, status]);

  const buildLinks = async () => {
    if (!query.trim()) return;
    setBusy(true); setErr('');
    try {
      const r = await api.get('/sources/links', { params: { q: query, categories: category || undefined, limit: 500 } });
      setLinks(r.data.links || []);
    } catch (e) { setErr(e.response?.data?.error || e.message); }
    setBusy(false);
  };

  const runVerify = async () => {
    setBusy(true); setErr('');
    try {
      const r = await api.post('/sources/verify', { query: query || 'John Smith', timeout: 12 }, { timeout: 300000 });
      setVerify(r.data);
    } catch (e) { setErr(e.response?.data?.error || e.message); }
    setBusy(false);
  };

  return (
    <div style={S.section}>
      <h2 style={S.title}>Unified Source Registry</h2>
      <p style={S.sub}>
        {catalog?.total || 0} public sources across global/regional web, people, records, academic,
        code, social, image, infrastructure and monitoring. Verified means live-checked; adapter
        means code exists but a live check is still recommended. Link-out and blocked sources are
        never counted as automatic hits.
      </p>
      <Stats items={[
        ['total', catalog?.total], ['verified', catalog?.verified], ['adapter', catalog?.adapter],
        ['queryable', catalog?.queryable], ['optional key', catalog?.optional_key],
        ['link-out', catalog?.link_out], ['blocked', catalog?.blocked],
        ['error', catalog?.error], ['cataloged', catalog?.cataloged],
      ]} />
      <div style={S.row}>
        <input style={{ ...S.input, flex:2, minWidth:220 }} value={filter} placeholder="filter id / label / adapter / type"
          onChange={e => setFilter(e.target.value)} />
        <select style={S.select} value={category} onChange={e => setCategory(e.target.value)}>
          <option value="">all categories</option>
          {Object.keys(catalog?.by_category || {}).sort().map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <select style={S.select} value={access} onChange={e => setAccess(e.target.value)}>
          <option value="">all access</option>
          {(catalog?.access_modes || []).map(a => <option key={a} value={a}>{a}</option>)}
        </select>
        <select style={S.select} value={status} onChange={e => setStatus(e.target.value)}>
          <option value="">all status</option>
          {Object.keys(catalog?.by_status || {}).sort().map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <button style={S.ghost} onClick={load} disabled={busy}>Reload</button>
      </div>
      <div style={{ ...S.row, marginTop:10 }}>
        <input style={{ ...S.input, flex:2, minWidth:220 }} value={query} placeholder="build public link-outs for a query"
          onChange={e => setQuery(e.target.value)} onKeyDown={e => e.key === 'Enter' && buildLinks()} />
        <button style={S.btn} onClick={buildLinks} disabled={busy}>Build links</button>
        <button style={S.ghost} onClick={runVerify} disabled={busy}>Live-verify keyless adapters</button>
      </div>
      <Err e={err} />
      {links.length > 0 && (
        <div style={{ ...S.card, marginTop:12 }}>
          <div style={S.label}>public link-outs ({links.length})</div>
          <div style={S.row}>{links.map((x, i) => (
            <a key={i} href={x.url} target="_blank" rel="noopener noreferrer" style={{ ...S.tag, color:'#58a6ff', textDecoration:'none' }}
              title={`${x.category} · ${x.access} · ${x.status}`}>{x.label}</a>
          ))}</div>
        </div>
      )}
      {verify && (
        <div style={{ ...S.card, marginTop:12 }}>
          <div style={S.label}>live verification</div>
          <div style={S.row}>
            <span style={S.tag}>checked {verify.checked}</span>
            <span style={S.tag}>ok {verify.ok}</span>
            <span style={S.tag}>empty {verify.empty}</span>
            <span style={S.tag}>blocked {verify.blocked}</span>
            <span style={S.tag}>error {verify.error}</span>
            <span style={S.tag}>no adapter {verify.no_adapter}</span>
          </div>
          <div style={{ ...S.row, marginTop:8 }}>
            {Object.entries(verify.results || {}).map(([id, v]) => (
              <span key={id} style={{ ...S.tag, color: v.status === 'ok' ? '#2ecc71' : v.status === 'blocked' ? '#e67e22' : '#8b949e' }}
                title={v.detail || ''}>{id} · {v.status}{v.count != null ? ` · ${v.count}` : ''}</span>
            ))}
          </div>
        </div>
      )}
      <div style={{ ...S.card, marginTop:12, overflowX:'auto' }}>
        <div style={S.label}>{rows.length} matching sources</div>
        <table style={S.table}>
          <thead><tr>
            <th style={S.th}>Source</th><th style={S.th}>Category</th><th style={S.th}>Access</th>
            <th style={S.th}>Status</th><th style={S.th}>Adapter</th><th style={S.th}>Region</th>
            <th style={S.th}>Key</th><th style={S.th}>Public URL</th>
          </tr></thead>
          <tbody>
            {rows.slice(0, 500).map(s => (
              <tr key={s.id}>
                <td style={S.td}><strong>{s.label}</strong><div style={S.mono}>{s.id}</div></td>
                <td style={S.td}>{s.category}</td><td style={S.td}>{s.access}</td>
                <td style={S.td}><span style={{ ...S.pill, background: s.status === 'blocked' ? '#e74c3c' : s.status === 'verified' ? '#27ae60' : '#8b949e' }}>{s.status}</span></td>
                <td style={S.td}>{s.adapter || ''}</td><td style={S.td}>{s.region}</td>
                <td style={S.td}>{s.requires_key ? (s.key_env || 'required') : ''}</td>
                <td style={S.td}>{s.search || s.profile_url || s.homepage ? <a href={s.search || s.profile_url || s.homepage} target="_blank" rel="noopener noreferrer" style={{ ...S.mono, color:'#58a6ff' }}>{s.search || s.profile_url || s.homepage}</a> : ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
