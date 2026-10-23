import React, { useState, useEffect } from 'react';

const K = {
  bg:'#010409', panel:'#0a0f1c', card:'#0d1117', line:'#1b2a44',
  cyan:'#00e5ff', green:'#39ff14', mag:'#ff2e63', amber:'#ffb300',
  dim:'#5c7a99', text:'#c9f3ff',
};
const S = {
  section:{background:K.panel,border:`1px solid ${K.line}`,borderRadius:10,padding:20,marginBottom:18,
    boxShadow:`0 0 18px ${K.cyan}22, inset 0 0 30px ${K.bg}`},
  title:{margin:'0 0 4px',fontSize:16,color:K.cyan,fontFamily:'ui-monospace,Menlo,monospace',
    letterSpacing:'0.06em',textShadow:`0 0 8px ${K.cyan}66`,textTransform:'uppercase'},
  sub:{margin:'0 0 14px',fontSize:12,color:K.dim},
  input:{background:'#010409',border:`1px solid ${K.line}`,color:K.text,borderRadius:6,
    padding:'9px 12px',fontSize:13,outline:'none',width:'100%',fontFamily:'ui-monospace,Menlo,monospace'},
  btn:{background:`linear-gradient(180deg,${K.cyan}22,${K.cyan}11)`,color:K.cyan,
    border:`1px solid ${K.cyan}55`,borderRadius:6,padding:'9px 16px',fontSize:12,cursor:'pointer',
    fontWeight:700,whiteSpace:'nowrap',fontFamily:'ui-monospace,Menlo,monospace',letterSpacing:'0.04em',
    textShadow:`0 0 6px ${K.cyan}88`},
  btnAlt:{background:`linear-gradient(180deg,${K.green}1a,${K.green}0a)`,color:K.green,
    border:`1px solid ${K.green}55`,borderRadius:6,padding:'9px 16px',fontSize:12,cursor:'pointer',
    fontWeight:700,fontFamily:'ui-monospace,Menlo,monospace',textShadow:`0 0 6px ${K.green}88`},
  btnMag:{background:`linear-gradient(180deg,${K.mag}1a,${K.mag}0a)`,color:K.mag,
    border:`1px solid ${K.mag}55`,borderRadius:6,padding:'9px 16px',fontSize:12,cursor:'pointer',
    fontWeight:700,fontFamily:'ui-monospace,Menlo,monospace',textShadow:`0 0 6px ${K.mag}88`},
  row:{display:'flex',gap:8,flexWrap:'wrap',alignItems:'center'},
  pill:{color:'#000',padding:'2px 9px',borderRadius:12,fontSize:11,fontWeight:700},
  tag:{background:'#010409',border:`1px solid ${K.line}`,color:K.cyan,padding:'2px 7px',
    borderRadius:4,fontSize:11,marginRight:4,fontFamily:'ui-monospace,Menlo,monospace'},
  card:{background:K.card,border:`1px solid ${K.line}`,borderRadius:8,padding:'14px 16px',marginBottom:10},
  mono:{fontFamily:'ui-monospace,Menlo,monospace',fontSize:12,wordBreak:'break-all',color:K.text},
  label:{fontSize:11,color:K.dim,display:'block',marginBottom:4,textTransform:'uppercase',letterSpacing:'0.06em'},
  select:{background:'#010409',border:`1px solid ${K.line}`,color:K.text,borderRadius:6,padding:'9px 10px',fontSize:13,
    fontFamily:'ui-monospace,Menlo,monospace'},
  pre:{fontFamily:'ui-monospace,Menlo,monospace',fontSize:11,color:K.green,whiteSpace:'pre-wrap',maxHeight:340,
    overflowY:'auto',background:'#010409',padding:12,borderRadius:6,margin:0,border:`1px solid ${K.line}`},
};
const Err = ({e}) => e ? <div style={{...S.card,border:`1px solid ${K.mag}`,background:'#1a0510',color:K.mag,fontSize:13,fontFamily:'ui-monospace,Menlo,monospace'}}>
  {typeof e==='string'?e:JSON.stringify(e)}</div> : null;
const Sec = ({title,sub,children}) => (
  <div style={S.section}>
    <h3 style={S.title}>{title}</h3>
    {sub && <p style={S.sub}>{sub}</p>}
    {children}
  </div>
);
const Pill = ({c,children}) => <span style={{...S.pill,background:c||K.cyan}}>{children}</span>;
const Status = ({s}) => {
  const c = s==='ok'?K.green : (s==='blocked'||s==='possible_hit')?K.amber : (s==='missing_dependency'||s==='error')?K.mag : K.dim;
  return <Pill c={c}>{String(s||'—')}</Pill>;
};

// ================================================================ OFFENSIVE WEB INTEL + BROKER + PINS
export function BonusPanel({ api }) {
  const [cases,setCases]=useState([]); const [cid,setCid]=useState('');
  const [url,setUrl]=useState(''); const [stack,setStack]=useState(null); const [pay,setPay]=useState(null);
  const [shorten,setShorten]=useState(null);
  const [canaryIn,setCanaryIn]=useState(''); const [canary,setCanary]=useState(null);
  const [name,setName]=useState(''); const [broker,setBroker]=useState(null);
  const [pinLabel,setPinLabel]=useState(''); const [pinLat,setPinLat]=useState(''); const [pinLon,setPinLon]=useState('');
  const [pins,setPins]=useState([]); const [bundle,setBundle]=useState(null); const [passes,setPasses]=useState(null);
  const [busy,setBusy]=useState(''); const [err,setErr]=useState('');

  useEffect(()=>{
    api.get('/cases').then(r=>setCases(Array.isArray(r.data)?r.data:(r.data?.cases||[]))).catch(()=>{});
    api.get('/pins').then(r=>setPins(r.data?.pins||[])).catch(()=>{});
  },[api]);

  const run=async(label,fn)=>{ setBusy(label); setErr(''); try{await fn();}catch(e){setErr(e.response?.data?.error||e.message);} setBusy(''); };
  const body=()=>({case_id:cid?+cid:undefined});
  const doStack=()=>run('stack',async()=>{const r=await api.post('/offsec/stack',{url,...body()});setStack(r.data);});
  const doPay=()=>run('pay',async()=>{const r=await api.post('/offsec/payments',{url,...body()});setPay(r.data);});
  const doShort=()=>run('short',async()=>{const r=await api.post('/offsec/shortener',{url,...body()});setShorten(r.data);});
  const doCanary=()=>run('canary',async()=>{const r=await api.post('/offsec/canary',{payload:canaryIn,source:'evidence',...body()});setCanary(r.data);});
  const doBroker=()=>run('broker',async()=>{const r=await api.post('/broker/sweep',{name,...body()});setBroker(r.data);});
  const doPin=()=>run('pin',async()=>{
    const r=await api.post('/pins',{label:pinLabel,lat:+pinLat,lon:+pinLon,...body()});
    const l=await api.get('/pins');setPins(l.data?.pins||[]);
    if(r.data?.id){const b=await api.get(`/pins/${r.data.id}`);setBundle(b.data);}
  });
  const doBundle=async(id)=>run('bundle',async()=>{const b=await api.get(`/pins/${id}`);setBundle(b.data);});
  const doPasses=async(id)=>run('passes',async()=>{const p=await api.get(`/pins/${id}/passes`);setPasses(p.data);});

  return (
    <div>
      <Sec title="Stack fingerprint" sub="Who runs on a target site: analytics, anti-bot walls, CDN, cookies and form actions. SSRF-guarded — private/reserved ranges are refused.">
        <div style={S.row}>
          <input style={{...S.input,flex:2,minWidth:220}} placeholder="https://target.example" value={url} onChange={e=>setUrl(e.target.value)} onKeyDown={e=>e.key==='Enter'&&doStack()}/>
          <select style={S.select} value={cid} onChange={e=>setCid(e.target.value)}>
            <option value="">no case</option>{cases.map(c=><option key={c.id} value={c.id}>{c.case_number||c.id} — {c.name}</option>)}
          </select>
          <button style={S.btn} onClick={doStack} disabled={!url||busy}>{busy==='stack'?'Fingerprinting…':'Fingerprint'}</button>
          <button style={S.btnAlt} onClick={doPay} disabled={!url||busy}>Payment addrs</button>
          <button style={S.btnAlt} onClick={doShort} disabled={!url||busy}>Shortener</button>
        </div>
        <Err e={err}/>
        {stack && (
          <div style={{...S.card,marginTop:12}}>
            <div style={S.label}>stack — {stack.url}</div>
            <Status s={stack.status}/>
            <div style={{...S.label,marginTop:10}}>trackers ({stack.counts?.trackers})</div>
            <div>{Object.entries(stack.trackers||{}).map(([k,v])=><span key={k} style={S.tag} title={v.join(', ')}>{k}</span>)}</div>
            <div style={{...S.label,marginTop:10}}>anti-bot ({stack.counts?.anti_bot})</div>
            <div>{Object.entries(stack.anti_bot||{}).map(([k,v])=><span key={k} style={{...S.tag,color:K.mag,borderColor:K.mag}}>{k}</span>)}</div>
            <div style={{...S.label,marginTop:10}}>cdn / infra</div>
            <div>{Object.keys(stack.cdn||{}).map(k=><span key={k} style={S.tag}>{k}</span>)}
              {stack.server && <span style={S.tag}>srv:{stack.server}</span>}
              {stack.powered_by && <span style={S.tag}>{stack.powered_by}</span>}</div>
            {stack.cookies?.length>0 && (<>
              <div style={{...S.label,marginTop:10}}>cookies</div>
              <div>{stack.cookies.map(c=><span key={c} style={S.tag}>{c}</span>)}</div></>)}
          </div>
        )}
        {pay && (
          <div style={{...S.card,marginTop:12}}>
            <div style={S.label}>payment addresses — {pay.pages_scanned} pages · {pay.count} found</div>
            {(pay.addresses||[]).map(a=>(
              <div key={a.type+a.address} style={{...S.row,justifyContent:'space-between',marginBottom:4}}>
                <Pill c={a.type==='btc'?K.amber:a.type==='eth'?K.cyan:K.mag}>{a.type}</Pill>
                <span style={{...S.mono,flex:1}}>{a.address}</span>
              </div>
            ))}
          </div>
        )}
        {shorten && (
          <div style={{...S.card,marginTop:12}}>
            <div style={S.label}>redirect chain — {shorten.hops} hops{shorten.shortener?` via ${shorten.shortener}`:''}</div>
            {(shorten.chain||[]).map((h,i)=>(
              <div key={i} style={{...S.row,marginBottom:3}}>
                <span style={{color:K.dim,fontSize:11,fontFamily:'ui-monospace,Menlo,monospace'}}>{h.http||'→'}</span>
                <span style={{...S.mono,fontSize:11,flex:1}}>{h.url}</span>
              </div>
            ))}
            {Object.keys(shorten.campaign||{}).length>0 && (<>
              <div style={{...S.label,marginTop:8}}>campaign params</div>
              <pre style={S.pre}>{JSON.stringify(shorten.campaign,null,1)}</pre></>)}
          </div>
        )}
      </Sec>

      <Sec title="Canary / pixel detector" sub="Flag tracking pixels, phone-home beacons and long campaign tokens in received evidence (HTML, email body, pasted text).">
        <textarea style={{...S.input,minHeight:110,fontFamily:'ui-monospace,Menlo,monospace'}} placeholder="<img src='https://track.example/pixel.gif' width='1' height='1'> …"
          value={canaryIn} onChange={e=>setCanaryIn(e.target.value)}/>
        <div style={{...S.row,marginTop:8}}><button style={S.btnMag} onClick={doCanary} disabled={!canaryIn||busy}>{busy==='canary'?'Scanning…':'Scan evidence'}</button>
        {canary && <Pill c={canary.risk==='high'?K.mag:canary.risk==='medium'?K.amber:K.green}>risk: {canary.risk}</Pill>}</div>
        {canary && canary.findings?.length>0 && (
          <div style={{...S.card,marginTop:12}}>
            {canary.findings.map((f,i)=>(
              <div key={i} style={{...S.row,marginBottom:4,justifyContent:'space-between'}}>
                <Pill c={f.kind==='tracking_pixel'?K.mag:f.kind==='beacon_url'?K.amber:K.cyan}>{f.kind}</Pill>
                <span style={{...S.mono,flex:1,fontSize:11}}>{f.url||'—'}</span>
                <span style={{color:K.dim,fontSize:11}}>{f.why}</span>
              </div>
            ))}
          </div>
        )}
      </Sec>

      <Sec title="Data-broker exposure sweep" sub="Walks a people-search catalog for a subject name. Honest statuses: possible_hit / no_signal / blocked (unknown, not clear). Rate-limited.">
        <div style={S.row}>
          <input style={{...S.input,flex:2,minWidth:220}} placeholder="full name" value={name} onChange={e=>setName(e.target.value)} onKeyDown={e=>e.key==='Enter'&&doBroker()}/>
          <button style={S.btn} onClick={doBroker} disabled={!name||busy}>{busy==='broker'?'Sweeping…':'Sweep catalog'}</button>
        </div>
        {broker && (
          <div style={{...S.card,marginTop:12}}>
            <div style={{...S.row,gap:16,marginBottom:8}}>
              <span style={{color:K.dim,fontSize:12}}>hits <b style={{color:K.amber}}>{broker.hits}</b></span>
              <span style={{color:K.dim,fontSize:12}}>clean <b style={{color:K.green}}>{broker.clean}</b></span>
              <span style={{color:K.dim,fontSize:12}}>blocked <b style={{color:K.mag}}>{broker.blocked}</b></span>
              <span style={{color:K.dim,fontSize:12}}>exposure <b style={{color:K.cyan}}>{broker.exposure_score??'—'}%</b></span>
            </div>
            {(broker.results||[]).map(r=>(
              <div key={r.id} style={{...S.row,justifyContent:'space-between',marginBottom:4}}>
                <span style={{color:K.text,fontSize:12,fontFamily:'ui-monospace,Menlo,monospace'}}>{r.label}</span>
                <Status s={r.status}/>
                {r.evidence && <span style={{color:K.dim,fontSize:11}}>{r.evidence}</span>}
              </div>
            ))}
            <div style={{color:K.dim,fontSize:11,marginTop:8}}>{broker.note}</div>
          </div>
        )}
      </Sec>

      <Sec title="Location pins" sub="Persistent geofences: buildings, POIs, aerial + street imagery, Shodan OT exposure, OpenCelliD towers and label news in one bundle. Diff on check, SGP4 pass schedule on demand.">
        <div style={S.row}>
          <input style={{...S.input,flex:1,minWidth:140}} placeholder="label" value={pinLabel} onChange={e=>setPinLabel(e.target.value)}/>
          <input style={{...S.input,width:110}} placeholder="lat" value={pinLat} onChange={e=>setPinLat(e.target.value)}/>
          <input style={{...S.input,width:110}} placeholder="lon" value={pinLon} onChange={e=>setPinLon(e.target.value)}/>
          <button style={S.btnAlt} onClick={doPin} disabled={!pinLabel||!pinLat||!pinLon||busy}>{busy==='pin'?'Creating…':'Create pin'}</button>
        </div>
        <Err e={err}/>
        {pins.map(p=>(
          <div key={p.id} style={{...S.card,marginTop:10}}>
            <div style={{...S.row,justifyContent:'space-between'}}>
              <div>
                <strong style={{color:K.cyan,fontSize:14,fontFamily:'ui-monospace,Menlo,monospace'}}>{p.label}</strong>
                <div style={{...S.mono,color:K.dim,fontSize:11}}>{p.lat}, {p.lon} · r={p.radius_m}m{p.case_id?` · case ${p.case_id}`:''}</div>
              </div>
              <div style={S.row}>
                <button style={S.btn} onClick={()=>doBundle(p.id)}>bundle</button>
                <button style={S.btnAlt} onClick={()=>doPasses(p.id)}>passes</button>
              </div>
            </div>
          </div>
        ))}
        {bundle && (
          <div style={{...S.card,marginTop:12,border:`1px solid ${K.green}55`}}>
            <div style={S.label}>bundle — {bundle.pin?.label}</div>
            {Object.entries(bundle).filter(([k])=>!['pin'].includes(k)).map(([k,v])=>(
              <div key={k} style={{...S.row,justifyContent:'space-between',marginBottom:3}}>
                <span style={{color:K.text,fontSize:12,fontFamily:'ui-monospace,Menlo,monospace'}}>{k}</span>
                <Status s={v?.status}/>
                <span style={{color:K.dim,fontSize:11}}>{v?.count ?? (v?.error?String(v.error).slice(0,60):'')}</span>
              </div>
            ))}
          </div>
        )}
        {passes && (
          <div style={{...S.card,marginTop:12}}>
            <div style={S.label}>satellite passes — {passes.label}</div>
            <Status s={passes.status}/>
            {passes.status==='missing_dependency' && <div style={{color:K.amber,fontSize:12,marginTop:6,fontFamily:'ui-monospace,Menlo,monospace'}}>{passes.install||'pip install sgp4'}</div>}
            {(passes.passes||[]).map((p,i)=>(
              <div key={i} style={{...S.row,justifyContent:'space-between',marginBottom:4}}>
                <span style={{color:K.text,fontSize:12,fontFamily:'ui-monospace,Menlo,monospace'}}>{p.satellite}</span>
                <span style={{...S.mono,fontSize:11,flex:1}}>{p.start} → {p.end}</span>
                <span style={{color:K.cyan,fontSize:11}}>max {p.max_elev}°</span>
                <Pill c={p.view==='clear'?K.green:p.view==='overcast'?K.mag:K.dim}>{p.cloud_cover_pct??'—'}% {p.view}</Pill>
              </div>
            ))}
          </div>
        )}
      </Sec>
    </div>
  );
}
