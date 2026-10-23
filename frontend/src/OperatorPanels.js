import React, { useState, useEffect, useCallback } from 'react';

// Shared inline styles matching the Xaxglog dark theme.
const S = {
  section: { background:'#161b22', border:'1px solid #30363d', borderRadius:8, padding:20, marginBottom:20 },
  title:   { margin:'0 0 4px', fontSize:16, color:'#e6edf3' },
  sub:     { margin:'0 0 14px', fontSize:12, color:'#8b949e' },
  input:   { background:'#0d1117', border:'1px solid #30363d', color:'#e6edf3', borderRadius:6,
             padding:'9px 12px', fontSize:13, outline:'none', width:'100%' },
  btn:     { background:'#1f6feb', color:'#fff', border:'none', borderRadius:6, padding:'9px 16px',
             fontSize:13, cursor:'pointer', fontWeight:600, whiteSpace:'nowrap' },
  row:     { display:'flex', gap:8, flexWrap:'wrap', alignItems:'center' },
  pill:    { color:'#fff', padding:'2px 9px', borderRadius:12, fontSize:11, fontWeight:600 },
  tag:     { background:'#21262d', color:'#8b949e', padding:'2px 7px', borderRadius:4, fontSize:11, marginRight:4 },
  card:    { background:'#0d1117', border:'1px solid #30363d', borderRadius:8, padding:'14px 16px', marginBottom:10 },
  mono:    { fontFamily:'ui-monospace,Menlo,monospace', fontSize:12, wordBreak:'break-all' },
  label:   { fontSize:11, color:'#8b949e', display:'block', marginBottom:4, textTransform:'uppercase', letterSpacing:'0.04em' },
  table:   { width:'100%', borderCollapse:'collapse', fontSize:12 },
  th:      { background:'#161b22', padding:'8px 10px', textAlign:'left', color:'#8b949e', fontWeight:600, borderBottom:'1px solid #30363d' },
  td:      { padding:'8px 10px', borderBottom:'1px solid #21262d', color:'#e6edf3' },
  select:  { background:'#0d1117', border:'1px solid #30363d', color:'#e6edf3', borderRadius:6, padding:'9px 10px', fontSize:13 },
};
const sevColour = (s) => ({critical:'#e74c3c',high:'#e67e22',medium:'#f1c40f',low:'#3498db',info:'#8b949e'}[s]||'#8b949e');
const riskColour = (r) => ({high:'#e74c3c',medium:'#e67e22',low:'#f1c40f',none_detected:'#2ecc71'}[r]||'#8b949e');

const Err = ({e}) => e ? (
  <div style={{...S.card, border:'1px solid #e74c3c', background:'#2a1a1a', color:'#e74c3c', fontSize:13}}>
    {typeof e === 'string' ? e : JSON.stringify(e)}
  </div>) : null;

// ---------------------------------------------------------------- Recon Pipeline
export function ReconPanel({ api }) {
  const [target, setTarget] = useState('');
  const [type, setType] = useState('domain');
  const [caseId, setCaseId] = useState('');
  const [res, setRes] = useState(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [deepRes, setDeepRes] = useState(null);
  const [deepBusy, setDeepBusy] = useState(false);

  const run = async () => {
    if (!target.trim()) return;
    setBusy(true); setErr(''); setRes(null);
    try {
      const r = await api.post('/recon/run', { target, type, case_id: caseId ? +caseId : null });
      setRes(r.data);
    } catch (e) { setErr(e.response?.data?.error || e.message); }
    setBusy(false);
  };

  const runDeep = async () => {
    if (!target.trim()) return;
    setDeepBusy(true); setErr(''); setDeepRes(null);
    try {
      const r = await api.post('/recon/deep', { target, case_id: caseId ? +caseId : null }, { timeout: 240000 });
      setDeepRes(r.data);
    } catch (e) { setErr(e.response?.data?.error || e.message); }
    setDeepBusy(false);
  };

  return (
    <div style={S.section}>
      <h2 style={S.title}>Deep Recon Pipeline</h2>
      <p style={S.sub}>Chained reconnaissance — a domain fans out to subdomains, DNS, TLS SANs, IPs, ASN/geo and exposed contacts, each stage feeding the next. Results attach to the case graph with evidence hashes.</p>
      <div style={S.row}>
        <input style={{...S.input, flex:1, minWidth:200}} placeholder="target (e.g. Jane Doe, jane@example.com, example.com, 8.8.8.8)"
          value={target} onChange={e=>setTarget(e.target.value)} onKeyDown={e=>e.key==='Enter'&&run()} />
        <select style={S.select} value={type} onChange={e=>setType(e.target.value)}>
          <option value="domain">domain</option><option value="ip">ip</option>
        </select>
        <input style={{...S.input, width:110}} placeholder="case id" value={caseId} onChange={e=>setCaseId(e.target.value)} />
        <button style={S.btn} onClick={run} disabled={busy}>{busy?'Running…':'Run pipeline'}</button>
        <button style={{...S.btn, background:'#e67e22'}} onClick={runDeep} disabled={deepBusy}>
          {deepBusy?'Digging…':'Intense recon'}
        </button>
      </div>
      <p style={{...S.sub, marginTop:6, color:'#8b949e'}}>
        Intense recon auto-detects the target class (person / company / domain / vehicle / phone) and recursively
        drives the matching modules — identity fan-out, ownership chains, crawl + archive + leak + netblock + ports.
      </p>
      <Err e={err} />
      {deepRes && (
        <div style={{marginTop:14, border:'1px solid #e67e22', borderRadius:8, padding:14}}>
          <div style={{...S.row, marginBottom:10}}>
            <span style={{...S.pill, background:'#e67e22'}}>{deepRes.detected_type}</span>
            <span style={{color:'#8b949e', fontSize:12}}>intense recon · {deepRes.elapsed}s · axes: {deepRes.axes_run?.join(', ')}</span>
          </div>
          <div style={{marginBottom:10}}>
            {Object.entries(deepRes.axis_status || {}).map(([k, v]) => (
              <span key={k} style={{...S.pill, background: v==='ok'?'#27ae60':(v==='error'?'#c0392b':'#7f8c8d'), marginRight:6, marginBottom:4, display:'inline-block'}}>
                {k}: {v}
              </span>
            ))}
          </div>
          {deepRes.dossier && (
            <div style={{...S.card, marginBottom:12}}>
              <div style={{...S.row, marginBottom:10}}>
                <span style={{...S.pill, background: deepRes.dossier.confidence?.band==='high'?'#27ae60':(deepRes.dossier.confidence?.band==='medium'?'#e67e22':'#7f8c8d')}}>
                  {(deepRes.dossier.confidence?.band || 'low').toUpperCase()}
                </span>
                <span style={{color:'#8b949e', fontSize:12}}>
                  confidence {deepRes.dossier.confidence?.score || 0}/100 · {deepRes.dossier.entities?.length || 0} entities
                </span>
                {(deepRes.dossier.confidence?.reasons || []).map((r, i) => (
                  <span key={i} style={S.tag}>{r}</span>
                ))}
              </div>
              <div style={{...S.row, marginBottom:10}}>
                {Object.entries(deepRes.dossier.counts || {}).filter(([, v]) => v).map(([k, v]) => (
                  <span key={k} style={S.tag}>{k}: {v}</span>
                ))}
              </div>
              <div style={{maxHeight:220, overflowY:'auto'}}>
                <table style={S.table}>
                  <thead><tr><th style={S.th}>type</th><th style={S.th}>value</th><th style={S.th}>source</th></tr></thead>
                  <tbody>
                    {(deepRes.dossier.entities || []).slice(0, 60).map((e, i) => (
                      <tr key={i}>
                        <td style={S.td}><span style={S.tag}>{e.type}</span></td>
                        <td style={S.td}>{e.url ? <a href={e.url} target="_blank" rel="noopener noreferrer" style={{color:'#58a6ff'}}>{e.value}</a> : e.value}</td>
                        <td style={{...S.td, color:'#8b949e'}}>{e.source}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
          {Object.entries(deepRes.axes || {}).map(([k, v]) => (
            <details key={k} style={S.card}>
              <summary style={{cursor:'pointer', color:'#e67e22', fontWeight:600, fontSize:13}}>{k}</summary>
              <pre style={{...S.mono, color:'#8b949e', marginTop:8, whiteSpace:'pre-wrap', maxHeight:260, overflowY:'auto'}}>
                {JSON.stringify(v, null, 2)}
              </pre>
            </details>
          ))}
        </div>
      )}
      {res && (
        <div style={{marginTop:14}}>
          <div style={{...S.row, marginBottom:10}}>
            <span style={{...S.pill, background:'#1f6feb'}}>{res.type}</span>
            <span style={{color:'#8b949e', fontSize:12}}>steps: {res.executed?.join(' → ')}</span>
          </div>
          {Object.entries(res.context||{}).map(([k,v]) => (
            <details key={k} style={{...S.card}}>
              <summary style={{cursor:'pointer', color:'#58a6ff', fontWeight:600, fontSize:13}}>{k}</summary>
              <pre style={{...S.mono, color:'#8b949e', marginTop:8, whiteSpace:'pre-wrap', maxHeight:240, overflowY:'auto'}}>
                {JSON.stringify(v, null, 2)}
              </pre>
            </details>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- Attribution / Profiler
export function AttributionPanel({ api }) {
  const [idents, setIdents] = useState('');
  const [caseId, setCaseId] = useState('');
  const [useAi, setUseAi] = useState(true);
  const [res, setRes] = useState(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const run = async () => {
    const list = idents.split(/[\s,]+/).map(x=>x.trim()).filter(Boolean);
    if (!list.length) return;
    setBusy(true); setErr(''); setRes(null);
    try {
      const r = await api.post('/attribution/profile',
        { identifiers:list, case_id: caseId?+caseId:null, use_ai:useAi });
      setRes(r.data);
    } catch (e) { setErr(e.response?.data?.error || e.message); }
    setBusy(false);
  };

  return (
    <div style={S.section}>
      <h2 style={S.title}>Attribution Profiler — actor tracing</h2>
      <p style={S.sub}>Feed known handles/emails/names. The profiler aggregates every discovered profile, correlates signals (shared username, cross-platform namespace, breach co-occurrence), and with an AI key produces a CERT-style actor assessment with a confidence band.</p>
      <textarea style={{...S.input, minHeight:64, resize:'vertical'}} placeholder={'one per line, e.g.\nhandle_x\nhandle_x@proton.me\n+15551234567'}
        value={idents} onChange={e=>setIdents(e.target.value)} />
      <div style={{...S.row, marginTop:8}}>
        <input style={{...S.input, width:110}} placeholder="case id" value={caseId} onChange={e=>setCaseId(e.target.value)} />
        <label style={{fontSize:12, color:'#8b949e'}}><input type="checkbox" checked={useAi} onChange={e=>setUseAi(e.target.checked)} /> AI narrative</label>
        <button style={S.btn} onClick={run} disabled={busy}>{busy?'Tracing…':'Build profile'}</button>
      </div>
      <Err e={err} />
      {res && (
        <div style={{marginTop:14}}>
          <div style={{...S.row, marginBottom:10}}>
            <span style={{...S.pill, background:sevColour(res.confidence==='high'?'high':res.confidence==='moderate'?'medium':'low')}}>
              confidence: {res.confidence}</span>
            <span style={{color:'#8b949e', fontSize:12}}>score {res.correlations?.score}/100</span>
          </div>
          {(res.correlations?.signals||[]).map((sg,i)=>(
            <div key={i} style={S.card}><span style={{...S.tag, background:'#1a2e3a', color:'#58a6ff'}}>{sg.signal}</span>
              <span style={{color:'#e6edf3', fontSize:12}}>{sg.note}</span></div>
          ))}
          {(res.profiles||[]).map((p,i)=>(
            <details key={i} style={S.card}>
              <summary style={{cursor:'pointer', color:'#58a6ff', fontWeight:600}}>{p.identifier} — {p.profiles?.length||0} profile(s)</summary>
              <div style={{marginTop:8}}>{(p.profiles||[]).map((pr,j)=>(
                <div key={j} style={{...S.row, marginBottom:4}}>
                  <span style={{...S.tag}}>{pr.platform}</span>
                  <a href={pr.url} target="_blank" rel="noreferrer" style={{...S.mono, color:'#58a6ff'}}>{pr.url}</a>
                </div>))}</div>
              {p.email_intel && <pre style={{...S.mono, color:'#8b949e', maxHeight:180, overflowY:'auto'}}>{JSON.stringify(p.email_intel.breaches,null,2)}</pre>}
            </details>
          ))}
          {res.ai_assessment && (
            <div style={{...S.card, border:'1px solid #8957e5'}}>
              <div style={{...S.pill, background:'#8957e5', display:'inline-block', marginBottom:8}}>AI ASSESSMENT</div>
              <div style={{whiteSpace:'pre-wrap', fontSize:13, lineHeight:1.6, color:'#e6edf3'}}>{typeof res.ai_assessment==='string'?res.ai_assessment:JSON.stringify(res.ai_assessment)}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- Dark Web
export function DarkWebPanel({ api }) {
  const [q, setQ] = useState('');
  const [caseId, setCaseId] = useState('');
  const [res, setRes] = useState(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const run = async () => {
    if (!q.trim()) return;
    setBusy(true); setErr(''); setRes(null);
    try { const r = await api.post('/darkweb/search', { query:q, case_id:caseId?+caseId:null }); setRes(r.data); }
    catch (e) { setErr(e.response?.data?.error || e.message); }
    setBusy(false);
  };
  const idx = res?.indexes||{};
  return (
    <div style={S.section}>
      <h2 style={S.title}>Dark-Web & Breach Search</h2>
      <p style={S.sub}>Indexed Tor search (Ahmia) + optional IntelX corpus + breach-corpus lookups. No crawling, no marketplace access — public indexes only.</p>
      <div style={S.row}>
        <input style={{...S.input, flex:1, minWidth:180}} placeholder="query, email, or handle" value={q}
          onChange={e=>setQ(e.target.value)} onKeyDown={e=>e.key==='Enter'&&run()} />
        <input style={{...S.input, width:110}} placeholder="case id" value={caseId} onChange={e=>setCaseId(e.target.value)} />
        <button style={{...S.btn, background:'#8957e5'}} onClick={run} disabled={busy}>{busy?'Searching…':'Search'}</button>
      </div>
      <Err e={err} />
      {idx.ahmia && (
        <div style={{marginTop:14}}>
          <div style={{...S.label, color:'#8957e5'}}>Ahmia index — {idx.ahmia.count??0} result(s)</div>
          {(idx.ahmia.results||[]).slice(0,25).map((r,i)=>(
            <div key={i} style={S.card}>
              <div style={{color:'#e6edf3', fontSize:13}}>{r.title||'(untitled)'}</div>
              <a href={r.url} target="_blank" rel="noreferrer" style={{...S.mono, color:'#a371f7'}}>{r.url}</a>
            </div>
          ))}
        </div>
      )}
      {idx.breaches && (
        <div style={{marginTop:14}}>
          <div style={{...S.label, color:'#e67e22'}}>Breach corpus</div>
          <pre style={{...S.mono, color:'#8b949e', maxHeight:220, overflowY:'auto'}}>{JSON.stringify(idx.breaches.breaches,null,2)}</pre>
        </div>
      )}
      {idx.intelx && <pre style={{...S.card, ...S.mono, color:'#8b949e'}}>{JSON.stringify(idx.intelx,null,2)}</pre>}
    </div>
  );
}

// ---------------------------------------------------------------- SIM-swap
export function SimSwapPanel({ api }) {
  const [num, setNum] = useState('');
  const [caseId, setCaseId] = useState('');
  const [res, setRes] = useState(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const run = async () => {
    if (!num.trim()) return;
    setBusy(true); setErr(''); setRes(null);
    try { const r = await api.post('/simswap/assess', { number:num, case_id:caseId?+caseId:null }); setRes(r.data); }
    catch (e) { setErr(e.response?.data?.error || e.message); }
    setBusy(false);
  };
  return (
    <div style={S.section}>
      <h2 style={S.title}>SIM-Swap Risk Detection</h2>
      <p style={S.sub}>Fraud-investigation risk scoring from public number-intelligence signals (carrier/line-type/porting indicators). Detection only — correlate with carrier records via lawful request to confirm.</p>
      <div style={S.row}>
        <input style={{...S.input, flex:1, minWidth:180}} placeholder="+15551234567" value={num}
          onChange={e=>setNum(e.target.value)} onKeyDown={e=>e.key==='Enter'&&run()} />
        <input style={{...S.input, width:110}} placeholder="case id" value={caseId} onChange={e=>setCaseId(e.target.value)} />
        <button style={{...S.btn, background:'#e67e22'}} onClick={run} disabled={busy}>{busy?'Assessing…':'Assess'}</button>
      </div>
      <Err e={err} />
      {res && (
        <div style={{marginTop:14}}>
          <div style={{...S.row, marginBottom:10}}>
            <span style={{...S.pill, background:riskColour(res.risk)}}>risk: {res.risk}</span>
            <span style={{color:'#8b949e', fontSize:12}}>score {res.score}/100</span>
            {res.evidence && <span style={{...S.mono, color:'#2ecc71'}}>evidence ✓</span>}
          </div>
          <div style={S.card}>
            <div style={{color:'#e6edf3', fontSize:13}}>{res.international||res.input}</div>
            <div style={{color:'#8b949e', fontSize:12, marginTop:4}}>carrier: {res.carrier||'—'} · region: {res.region||'—'} · line: {res.line_type||'—'}</div>
          </div>
          {(res.signals||[]).map((sg,i)=>(
            <div key={i} style={{...S.card, border:'1px solid #e67e22'}}>
              <span style={{...S.tag, background:'#2a1e0a', color:'#e67e22'}}>{sg.signal} (+{sg.weight})</span>
              <span style={{color:'#e6edf3', fontSize:12}}>{sg.note}</span>
            </div>
          ))}
          <div style={{color:'#8b949e', fontSize:11, marginTop:8, fontStyle:'italic'}}>{res.disclaimer}</div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- SS7 (authorized)
export function SS7Panel({ api }) {
  const [rt, setRt] = useState('location');
  const [msisdn, setMsisdn] = useState('');
  const [imsi, setImsi] = useState('');
  const [authRef, setAuthRef] = useState('');
  const [caseId, setCaseId] = useState('');
  const [res, setRes] = useState(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const run = async () => {
    setBusy(true); setErr(''); setRes(null);
    try {
      const params = { msisdn }; if (imsi) params.imsi = imsi;
      const r = await api.post('/ss7/request',
        { req_type:rt, params, authority_ref:authRef, case_id:caseId?+caseId:null });
      setRes(r.data);
    } catch (e) { setErr(JSON.stringify(e.response?.data||e.message)); }
    setBusy(false);
  };
  return (
    <div style={S.section}>
      <h2 style={S.title}>SS7 Lookup — authorized carrier request</h2>
      <p style={S.sub}>Lawful SS7 data (location/roaming/subscriber/CDR) is obtained through carrier lawful-access channels. Requests are authority-gated, hashed, and audited. With no gateway configured, requests export for manual carrier submission.</p>
      <div style={S.row}>
        <select style={S.select} value={rt} onChange={e=>setRt(e.target.value)}>
          <option value="location">location</option><option value="roaming">roaming</option>
          <option value="subscriber">subscriber</option><option value="cdr">cdr</option>
        </select>
        <input style={{...S.input, flex:1, minWidth:150}} placeholder="MSISDN (+15551234567)" value={msisdn} onChange={e=>setMsisdn(e.target.value)} />
        {rt==='location' && <input style={{...S.input, flex:1, minWidth:130}} placeholder="IMSI" value={imsi} onChange={e=>setImsi(e.target.value)} />}
      </div>
      <div style={{...S.row, marginTop:8}}>
        <input style={{...S.input, flex:1, minWidth:180}} placeholder="lawful authority ref (warrant #)" value={authRef} onChange={e=>setAuthRef(e.target.value)} />
        <input style={{...S.input, width:110}} placeholder="case id" value={caseId} onChange={e=>setCaseId(e.target.value)} />
        <button style={{...S.btn, background:'#2ecc71'}} onClick={run} disabled={busy}>{busy?'Submitting…':'Submit request'}</button>
      </div>
      <Err e={err} />
      {res && (
        <div style={{marginTop:14}}>
          <div style={{...S.card, border:'1px solid #2ecc71'}}>
            <div style={{color:'#2ecc71', fontWeight:600, fontSize:13}}>{res.note}</div>
            {res.evidence && <div style={{...S.mono, color:'#8b949e', marginTop:6}}>evidence hash: {res.evidence.hash}</div>}
          </div>
          {res.delivery?.payload && (
            <details style={S.card}><summary style={{cursor:'pointer', color:'#58a6ff'}}>export payload</summary>
              <pre style={{...S.mono, color:'#8b949e', whiteSpace:'pre-wrap'}}>{res.delivery.payload}</pre></details>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- Cases + Graph + Evidence
export function CasesPanel({ api }) {
  const [cases, setCases] = useState([]);
  const [active, setActive] = useState(null);
  const [graph, setGraph] = useState(null);
  const [form, setForm] = useState({name:'',description:'',legal_basis:''});
  const [search, setSearch] = useState('');
  const [searchRes, setSearchRes] = useState(null);
  const [evidence, setEvidence] = useState([]);
  const [alertList, setAlertList] = useState([]);
  const [watch, setWatch] = useState({entity_type:'email',entity_value:'',interval_min:360});
  const [msg, setMsg] = useState('');

  const load = useCallback(async () => {
    const r = await api.get('/cases'); setCases(r.data);
  }, [api]);
  useEffect(()=>{ load(); }, [load]);

  const create = async () => {
    if (!form.name) return;
    const r = await api.post('/cases', form);
    setForm({name:'',description:'',legal_basis:''});
    await load(); selectCase(r.data.id);
  };
  const selectCase = async (id) => {
    setActive(id);
    const [g, a] = await Promise.all([
      api.get(`/cases/${id}/graph`),
      api.get(`/alerts?case_id=${id}`),
    ]);
    setGraph(g.data); setAlertList(a.data);
    setEvidence([]);
  };
  const runSearch = async () => {
    if (!search.trim()) return;
    const r = await api.get(`/search?q=${encodeURIComponent(search)}&case_id=${active||''}`);
    setSearchRes(r.data);
  };
  const addWatch = async () => {
    if (!watch.entity_value || !active) return;
    await api.post('/watchlist', {...watch, case_id:active});
    setMsg('watch added'); setWatch({...watch, entity_value:''});
    setTimeout(()=>setMsg(''),2000);
  };
  const sweep = async () => { const r = await api.post('/watchlist/sweep'); setMsg(`swept, ${r.data.alerts_raised} alert(s)`); setTimeout(()=>setMsg(''),2500); };
  const verify = async (id) => {
    const r = await api.get(`/evidence/${id}/verify`);
    setMsg(`evidence #${id}: ${r.data.valid?'VALID ✓ (hash matches)':'TAMPERED ✗'}`);
    setTimeout(()=>setMsg(''),3500);
  };

  // simple force-ish circular layout for the graph (no external deps)
  const layout = (g) => {
    if (!g) return null;
    const nodes = g.nodes||[]; const n = nodes.length; const R = 180;
    const pos = {};
    const byType = {};
    nodes.forEach(nd => { (byType[nd.type] = byType[nd.type]||[]).push(nd); });
    const types = Object.keys(byType); const cx=220, cy=200;
    types.forEach((t,ti)=>{
      const ring = 60 + ti*40; const arr = byType[t];
      arr.forEach((nd,i)=>{ const ang = (i/Math.max(arr.length,1))*Math.PI*2 + ti;
        pos[nd.id] = {x:cx+ring*Math.cos(ang), y:cy+ring*Math.sin(ang)}; });
    });
    return {nodes, links:g.links||[], pos};
  };

  return (
    <div>
      <div style={S.section}>
        <h2 style={S.title}>Cases</h2>
        <p style={S.sub}>Every investigation runs inside a named, audited case with a stated legal basis. Findings attach as entities + hashed evidence.</p>
        <div style={S.row}>
          <input style={{...S.input, flex:1, minWidth:150}} placeholder="case name" value={form.name} onChange={e=>setForm({...form,name:e.target.value})}/>
          <input style={{...S.input, flex:2, minWidth:180}} placeholder="description" value={form.description} onChange={e=>setForm({...form,description:e.target.value})}/>
          <input style={{...S.input, flex:1, minWidth:140}} placeholder="legal basis (warrant #)" value={form.legal_basis} onChange={e=>setForm({...form,legal_basis:e.target.value})}/>
          <button style={S.btn} onClick={create}>Open case</button>
        </div>
        <div style={{marginTop:12}}>
          {cases.map(c=>(
            <div key={c.id} style={{...S.card, cursor:'pointer', border: active===c.id?'1px solid #1f6feb':'1px solid #30363d'}}
              onClick={()=>selectCase(c.id)}>
              <div style={{display:'flex', justifyContent:'space-between'}}>
                <span style={{color:'#e6edf3', fontWeight:600}}>{c.case_number} — {c.name}</span>
                <span style={{...S.tag}}>{c.status}</span>
              </div>
              <div style={{color:'#8b949e', fontSize:12, marginTop:2}}>{c.description}</div>
            </div>
          ))}
        </div>
      </div>

      {active && graph && (
        <div style={S.section}>
          <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', flexWrap:'wrap', gap:8}}>
            <h2 style={S.title}>Entity Graph — {graph.node_count} nodes / {graph.link_count} links</h2>
            <div style={S.row}>
              <span style={{...S.mono, color:'#2ecc71', fontSize:11}}>{msg}</span>
              <button style={{...S.btn, background:'#e67e22'}} onClick={sweep}>Sweep watchlist</button>
              <a href={`${api.defaults.baseURL}/report/${active}/html`} target="_blank" rel="noreferrer"
                style={{...S.btn, background:'#8957e5', textDecoration:'none'}}>Report</a>
              <a href={`${api.defaults.baseURL}/export/stix/${active}`} target="_blank" rel="noreferrer"
                style={{...S.btn, background:'#30363d', textDecoration:'none'}}>STIX</a>
            </div>
          </div>
          <svg width="440" height="400" style={{background:'#0d1117', border:'1px solid #30363d', borderRadius:8, width:'100%', maxWidth:520}}>
            {(() => { const L = layout(graph); if(!L) return null;
              return (<g>
                {L.links.map((l,i)=>{ const a=L.pos[l.src_id], b=L.pos[l.dst_id]; if(!a||!b) return null;
                  return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="#30363d" strokeWidth={Math.min((l.weight||1)*2,4)}/>; })}
                {L.nodes.map(nd=>{ const p=L.pos[nd.id]; if(!p) return null;
                  const col = {email:'#e74c3c',domain:'#1f6feb',ip:'#e67e22',phone:'#2ecc71',username:'#8957e5',handle:'#8957e5'}[nd.type]||'#8b949e';
                  return (<g key={nd.id}>
                    <circle cx={p.x} cy={p.y} r={6} fill={col}/>
                    <text x={p.x+8} y={p.y+3} fill="#8b949e" fontSize={8}>{String(nd.value).slice(0,18)}</text>
                  </g>); })}
              </g>); })()}
          </svg>
          <div style={{display:'flex', gap:6, flexWrap:'wrap', marginTop:8}}>
            {[['email','#e74c3c'],['domain','#1f6feb'],['ip','#e67e22'],['phone','#2ecc71'],['username/handle','#8957e5']].map(([t,c])=>(
              <span key={t} style={{fontSize:11, color:'#8b949e'}}><span style={{display:'inline-block',width:8,height:8,borderRadius:8,background:c,marginRight:4}}/>{t}</span>
            ))}
          </div>

          {/* Watchlist */}
          <div style={{marginTop:16}}>
            <div style={S.label}>Watch this case</div>
            <div style={S.row}>
              <select style={S.select} value={watch.entity_type} onChange={e=>setWatch({...watch,entity_type:e.target.value})}>
                <option value="email">email</option><option value="domain">domain</option><option value="username">username</option>
              </select>
              <input style={{...S.input, flex:1, minWidth:150}} placeholder="value to watch" value={watch.entity_value} onChange={e=>setWatch({...watch,entity_value:e.target.value})}/>
              <select style={S.select} value={watch.interval_min} onChange={e=>setWatch({...watch,interval_min:+e.target.value})}>
                <option value="60">hourly</option><option value="360">6-hourly</option><option value="1440">daily</option>
              </select>
              <button style={S.btn} onClick={addWatch}>Watch</button>
            </div>
          </div>

          {/* Alerts */}
          {alertList.length>0 && (
            <div style={{marginTop:14}}>
              <div style={S.label}>Alerts</div>
              {alertList.map(a=>(
                <div key={a.id} style={{...S.card, border:`1px solid ${sevColour(a.severity)}`}}>
                  <span style={{...S.pill, background:sevColour(a.severity)}}>{a.severity}</span>{' '}
                  <span style={{color:'#e6edf3', fontSize:13}}>{a.message}</span>
                </div>
              ))}
            </div>
          )}

          {/* Global search */}
          <div style={{marginTop:16}}>
            <div style={S.label}>Search all evidence</div>
            <div style={S.row}>
              <input style={{...S.input, flex:1}} placeholder="full-text search across artifacts" value={search}
                onChange={e=>setSearch(e.target.value)} onKeyDown={e=>e.key==='Enter'&&runSearch()}/>
              <button style={S.btn} onClick={runSearch}>Search</button>
            </div>
            {searchRes && (
              <div style={{marginTop:8}}>
                <div style={{color:'#8b949e', fontSize:12}}>{searchRes.results.length} hit(s) via {searchRes.mode}</div>
                {searchRes.results.map(r=>(
                  <div key={r.id} style={S.card}>
                    <div style={{...S.row}}>
                      <span style={{...S.tag, background:'#1a2e3a', color:'#58a6ff'}}>{r.type}</span>
                      <span style={{color:'#8b949e', fontSize:12}}>{r.source}</span>
                      <span style={{...S.mono, color:'#2ecc71', fontSize:10}}>#{r.id}</span>
                      <button style={{...S.btn, background:'#30363d', padding:'2px 8px', fontSize:11}} onClick={()=>verify(r.id)}>verify</button>
                    </div>
                    {r.snip && <div style={{...S.mono, color:'#e6edf3', marginTop:4}} dangerouslySetInnerHTML={{__html:r.snip}}/>}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
