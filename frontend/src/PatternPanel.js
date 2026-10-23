import React, { useState, useEffect } from 'react';

// Shared cyber styling for the pattern/offsec/broker/pins panels.
// Neon-on-dark, monospace, subtle glow — distinct from the base GitHub-dark theme.
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

// ================================================================ PATTERN TRACKER
export function PatternPanel({ api }) {
  const [cases,setCases]=useState([]); const [cid,setCid]=useState('');
  const [sources,setSources]=useState([]);
  const [entity,setEntity]=useState(''); const [plats,setPlats]=useState([]);
  const [collect,setCollect]=useState(null); const [contacts,setContacts]=useState(null);
  const [pnl,setPnl]=useState(null); const [org,setOrg]=useState(null);
  const [ingest,setIngest]=useState(''); const [ingestRes,setIngestRes]=useState(null);
  const [linkForm,setLinkForm]=useState({src_value:'',dst_value:'',relation:'contacts'});
  const [linkRes,setLinkRes]=useState(null);
  const [headers,setHeaders]=useState(''); const [emailRes,setEmailRes]=useState(null);
  const [busy,setBusy]=useState(''); const [err,setErr]=useState('');

  useEffect(()=>{
    api.get('/cases').then(r=>setCases(Array.isArray(r.data)?r.data:(r.data?.cases||[]))).catch(()=>{});
    api.get('/pattern/sources').then(r=>setSources(r.data?.sources||[])).catch(()=>{});
  },[api]);

  const run=async(label,fn)=>{ setBusy(label); setErr(''); try{await fn();}catch(e){setErr(e.response?.data?.error||e.message);} setBusy(''); };
  const doCollect=()=>run('collect',async()=>{
    const r=await api.post('/pattern/collect',{entity,case_id:cid?+cid:undefined,platforms:plats.length?plats:undefined});
    setCollect(r.data);
    const c=await api.get(`/pattern/frequent_contacts/${encodeURIComponent(entity)}`,{params:{case_id:cid?+cid:undefined}});
    setContacts(c.data);
    const p=await api.get(`/pattern/pnl/${encodeURIComponent(entity)}`,{params:{case_id:cid?+cid:undefined}});
    setPnl(p.data);
  });
  const doContacts=()=>run('contacts',async()=>{
    const c=await api.get(`/pattern/frequent_contacts/${encodeURIComponent(entity)}`,{params:{case_id:cid?+cid:undefined}});
    setContacts(c.data);
    const p=await api.get(`/pattern/pnl/${encodeURIComponent(entity)}`,{params:{case_id:cid?+cid:undefined}});
    setPnl(p.data);
  });
  const doOrg=()=>run('org',async()=>{ const r=await api.get(`/pattern/org/${encodeURIComponent(entity)}`,{params:{case_id:cid?+cid:undefined}}); setOrg(r.data); });
  const doIngest=()=>run('ingest',async()=>{
    let ev; try{ev=JSON.parse(ingest);}catch{setErr('ingest must be a JSON array of events');return;}
    const r=await api.post('/pattern/ingest',{events:ev,case_id:cid?+cid:undefined}); setIngestRes(r.data);
  });
  const doLink=()=>run('link',async()=>{
    const r=await api.post('/pattern/link',{...linkForm,case_id:cid?+cid:undefined}); setLinkRes(r.data);
  });
  const doEmail=()=>run('email',async()=>{
    const r=await api.post('/pattern/email_graph',{headers,case_id:cid?+cid:undefined}); setEmailRes(r.data);
  });
  const togglePlat=(p)=>setPlats(v=>v.includes(p)?v.filter(x=>x!==p):[...v,p]);
  const maxH = pnl ? Math.max(1,...pnl.active_hours?.hours_utc||[]) : 1;

  return (
    <div>
      <Sec title="Social Pattern Tracker" sub="Link a person/org to their handles, harvest cross-platform interactions, and rank frequent contacts with time-decayed scoring. Every event and link lands in the case graph.">
        <div style={S.row}>
          <input style={{...S.input,flex:2,minWidth:220}} placeholder="entity — handle / person / org / email" value={entity} onChange={e=>setEntity(e.target.value)} onKeyDown={e=>e.key==='Enter'&&doCollect()}/>
          <select style={S.select} value={cid} onChange={e=>setCid(e.target.value)}>
            <option value="">no case</option>{cases.map(c=><option key={c.id} value={c.id}>{c.case_number||c.id} — {c.name}</option>)}
          </select>
          <button style={S.btn} onClick={doCollect} disabled={!entity||busy}>{busy==='collect'?'Harvesting…':'Collect + Score'}</button>
          <button style={S.btnAlt} onClick={doContacts} disabled={!entity||busy}>Contacts</button>
          <button style={S.btnAlt} onClick={doOrg} disabled={!entity||busy}>Org View</button>
        </div>
        <div style={{...S.row,marginTop:10}}>
          <span style={{...S.label,margin:0}}>connectors:</span>
          {sources.map(s=>(
            <button key={s.platform} onClick={()=>togglePlat(s.platform)} title={s.target_hint}
              style={{...S.tag,cursor:'pointer',color:plats.includes(s.platform)?K.green:K.dim,
                border:`1px solid ${plats.includes(s.platform)?K.green:K.line}`}}>
              {plats.includes(s.platform)?'▸ ':'□ '}{s.platform}
            </button>
          ))}
        </div>
        <Err e={err}/>
        {collect && (
          <div style={{...S.card,marginTop:12}}>
            <div style={S.label}>Harvest — {collect.entity}</div>
            {Object.entries(collect.platforms||{}).map(([p,r])=>(
              <div key={p} style={{...S.row,justifyContent:'space-between',marginBottom:4}}>
                <span style={S.mono}>{p}</span>
                <Pill c={r.status==='ok'?K.green:(r.status==='blocked'?K.amber:K.mag)}>{r.status}</Pill>
                <span style={{color:K.dim,fontSize:11}}>{r.events_found??0} events</span>
              </div>
            ))}
            <div style={{color:K.cyan,fontSize:12,marginTop:6,fontFamily:'ui-monospace,Menlo,monospace'}}>
              ingested {collect.events?.inserted} · links {collect.links_created} · urls {collect.urls_recorded}
            </div>
          </div>
        )}
        {contacts && contacts.contacts?.length>0 && (
          <div style={{...S.card,marginTop:12}}>
            <div style={S.label}>Frequent contacts — {contacts.entity} (n={contacts.count}, half-life {contacts.half_life_days}d)</div>
            {contacts.contacts.map((c,i)=>(
              <div key={c.value+i} style={{...S.row,justifyContent:'space-between',marginBottom:5,borderBottom:`1px solid ${K.line}44`,paddingBottom:4}}>
                <span style={{...S.mono,color:c.qualified?K.green:K.dim}}>{i+1}. {c.value}</span>
                <span style={{color:K.cyan,fontSize:12,fontFamily:'ui-monospace,Menlo,monospace'}}>w={c.weight}</span>
                <span style={{color:K.dim,fontSize:11}}>{c.interactions}× · {c.sources} src{c.boost>1?` · ×${c.boost}`:''}</span>
                <div>{(c.platforms||[]).map(p=><span key={p} style={S.tag}>{p}</span>)}</div>
              </div>
            ))}
          </div>
        )}
        {pnl && (
          <div style={{...S.card,marginTop:12}}>
            <div style={S.label}>Pattern of life — {pnl.entity}</div>
            <div style={{...S.row,gap:16,marginBottom:10}}>
              <span style={{color:K.dim,fontSize:12}}>interactions <b style={{color:K.cyan}}>{pnl.interactions}</b></span>
              <span style={{color:K.dim,fontSize:12}}>cadence <b style={{color:K.cyan}}>{pnl.cadence?.per_day}/day</b></span>
              <span style={{color:K.dim,fontSize:12}}>peak <b style={{color:K.cyan}}>{pnl.peak_hour_utc??'—'}:00Z</b></span>
              <span style={{color:K.dim,fontSize:12}}>tz guess <b style={{color:K.green}}>{pnl.timezone?.local_label||'—'}</b> <span style={{color:K.dim}}>({pnl.timezone?.confidence??0})</span></span>
            </div>
            <div style={S.label}>active hours (UTC)</div>
            <div style={{display:'flex',gap:2,alignItems:'flex-end',height:60}}>
              {(pnl.active_hours?.hours_utc||[]).map((v,h)=>(
                <div key={h} title={`${h}:00Z — ${v}`} style={{flex:1,background:v?K.cyan:'#12203a',
                  height:`${Math.max(3,(v/maxH)*58)}px`,borderRadius:2,boxShadow:v?`0 0 6px ${K.cyan}66`:'none'}}/>
              ))}
            </div>
            <div style={{display:'flex',justifyContent:'space-between',color:K.dim,fontSize:10,fontFamily:'ui-monospace,Menlo,monospace',marginTop:2}}>
              <span>00</span><span>06</span><span>12</span><span>18</span><span>23Z</span>
            </div>
            {pnl.top_domains?.length>0 && (<>
              <div style={{...S.label,marginTop:12}}>top shared domains</div>
              <div>{pnl.top_domains.map(d=><span key={d.domain} style={S.tag}>{d.domain} ×{d.count}</span>)}</div>
            </>)}
            {pnl.ips?.length>0 && (<>
              <div style={{...S.label,marginTop:12}}>associated IPs (disclosed / infra)</div>
              <div>{pnl.ips.map(x=><span key={x.ip+x.source} style={S.tag} title={x.source}>{x.ip} · {x.source}</span>)}</div>
            </>)}
          </div>
        )}
        {org && (
          <div style={{...S.card,marginTop:12}}>
            <div style={S.label}>Org view — {org.org}</div>
            <div style={S.label}>members</div>
            <div>{(org.members||[]).map(m=><span key={m.value} style={S.tag}>{m.value} <span style={{color:K.dim}}>({m.confidence})</span></span>)}</div>
            <div style={{...S.label,marginTop:8}}>handles</div>
            <div>{(org.handles||[]).map(h=><span key={h.value+h.relation} style={S.tag}>{h.value}</span>)}</div>
          </div>
        )}
      </Sec>

      <Sec title="Manual ingest" sub="Paste a JSON array of normalized events to fold hand-collected intel into the store. Event shape: {actor,target,platform,kind,ts,url,text}.">
        <textarea style={{...S.input,minHeight:110,fontFamily:'ui-monospace,Menlo,monospace'}} placeholder='[{"actor":"@alice","target":"@bob","platform":"manual","kind":"reply","ts":"2026-10-01T12:00:00Z"}]'
          value={ingest} onChange={e=>setIngest(e.target.value)}/>
        <div style={{...S.row,marginTop:8}}><button style={S.btn} onClick={doIngest} disabled={!ingest||busy}>{busy==='ingest'?'Ingesting…':'Ingest events'}</button>
        {ingestRes && <span style={{color:K.green,fontSize:12,fontFamily:'ui-monospace,Menlo,monospace'}}>inserted {ingestRes.inserted} · skipped {ingestRes.skipped}</span>}</div>
      </Sec>

      <Sec title="Create link" sub="Assert an entity relationship (member_of / handle_of / contacts / shares_url / resolves_to). Types are auto-guessed when left blank.">
        <div style={S.row}>
          <input style={{...S.input,flex:1}} placeholder="src value" value={linkForm.src_value} onChange={e=>setLinkForm({...linkForm,src_value:e.target.value})}/>
          <select style={S.select} value={linkForm.relation} onChange={e=>setLinkForm({...linkForm,relation:e.target.value})}>
            {['member_of','handle_of','contacts','shares_url','resolves_to','affiliated','co_worker'].map(r=><option key={r} value={r}>{r}</option>)}
          </select>
          <input style={{...S.input,flex:1}} placeholder="dst value" value={linkForm.dst_value} onChange={e=>setLinkForm({...linkForm,dst_value:e.target.value})}/>
          <button style={S.btnAlt} onClick={doLink} disabled={!linkForm.src_value||!linkForm.dst_value||busy}>Link</button>
        </div>
        {linkRes && <div style={{color:K.green,fontSize:12,marginTop:8,fontFamily:'ui-monospace,Menlo,monospace'}}>
          {linkRes.created?'created':'updated'} link #{linkRes.id}{linkRes.graph?' · graph '+linkRes.graph.src_id+'→'+linkRes.graph.dst_id:''}</div>}
      </Sec>

      <Sec title="Email relationship graph" sub="Paste raw RFC-822 headers (one or many). Reconstructs threads via Message-ID / In-Reply-To / References, ranks participants, and flags auto-responder (OOO) patterns.">
        <textarea style={{...S.input,minHeight:130,fontFamily:'ui-monospace,Menlo,monospace'}}
          placeholder={'From: a@x.com\nTo: b@y.com\nSubject: Re: lead\nMessage-ID: <1@x>\nDate: Wed, 21 Oct 2026 12:00:00 +0000'}
          value={headers} onChange={e=>setHeaders(e.target.value)}/>
        <div style={{...S.row,marginTop:8}}><button style={S.btn} onClick={doEmail} disabled={!headers||busy}>{busy==='email'?'Analysing…':'Map threads'}</button>
        {emailRes?.ooo_signal && <Pill c={K.mag}>OOO signal detected</Pill>}</div>
        {emailRes && (
          <div style={{...S.card,marginTop:12}}>
            <div style={S.label}>{emailRes.messages} messages · {emailRes.thread_count} threads</div>
            {(emailRes.participants||[]).map(p=>(
              <div key={p.email} style={{...S.row,justifyContent:'space-between',marginBottom:4}}>
                <span style={{...S.mono,color:p.auto_replies?K.amber:K.text}}>{p.email}</span>
                <span style={{color:K.dim,fontSize:11}}>{p.sends} sent{p.auto_replies?` · ${p.auto_replies} auto`:''}</span>
              </div>
            ))}
            <pre style={S.pre}>{JSON.stringify(emailRes.graph_edges?.slice(0,10),null,1)}</pre>
          </div>
        )}
      </Sec>
    </div>
  );
}
