import React, { useState, useEffect, useCallback } from 'react';

import { S as CYBER_S } from './cyberTheme';

// Legacy values are kept for any panel-specific keys; CYBERDECK theme
// values win for every shared key.
const LEGACY_S = {
  section:{background:'#161b22',border:'1px solid #30363d',borderRadius:8,padding:20,marginBottom:20},
  title:{margin:'0 0 4px',fontSize:16,color:'#e6edf3'},
  sub:{margin:'0 0 14px',fontSize:12,color:'#8b949e'},
  input:{background:'#0d1117',border:'1px solid #30363d',color:'#e6edf3',borderRadius:6,padding:'9px 12px',fontSize:13,outline:'none',width:'100%'},
  btn:{background:'#1f6feb',color:'#fff',border:'none',borderRadius:6,padding:'9px 16px',fontSize:13,cursor:'pointer',fontWeight:600,whiteSpace:'nowrap'},
  row:{display:'flex',gap:8,flexWrap:'wrap',alignItems:'center'},
  pill:{color:'#fff',padding:'2px 9px',borderRadius:12,fontSize:11,fontWeight:600},
  tag:{background:'#21262d',color:'#8b949e',padding:'2px 7px',borderRadius:4,fontSize:11,marginRight:4},
  card:{background:'#0d1117',border:'1px solid #30363d',borderRadius:8,padding:'14px 16px',marginBottom:10},
  mono:{fontFamily:'ui-monospace,Menlo,monospace',fontSize:12,wordBreak:'break-all'},
  label:{fontSize:11,color:'#8b949e',display:'block',marginBottom:4,textTransform:'uppercase',letterSpacing:'0.04em'},
  select:{background:'#0d1117',border:'1px solid #30363d',color:'#e6edf3',borderRadius:6,padding:'9px 10px',fontSize:13},
  pre:{fontFamily:'ui-monospace,Menlo,monospace',fontSize:11,color:'#8b949e',whiteSpace:'pre-wrap',maxHeight:320,overflowY:'auto',background:'#010409',padding:10,borderRadius:6,margin:0},

};
const S = { ...LEGACY_S, ...CYBER_S };
const Err = ({e}) => e ? <div style={{...S.card,border:'1px solid #e74c3c',background:'#2a1a1a',color:'#e74c3c',fontSize:13}}>{typeof e==='string'?e:JSON.stringify(e)}</div> : null;
const KV = ({k,v}) => <div><span style={{color:'#8b949e'}}>{k}: </span><span style={{color:'#e6edf3'}}>{v??'—'}</span></div>;
const St = ({s}) => <span style={{...S.pill,background:s==='ok'||s==='ok|blocked'||s==='valid'?'#2ecc71':(s==='blocked'||s==='not_found'?'#e67e22':'#8b949e')}}>{String(s||'—')}</span>;
const Section = ({title,sub,children}) => (
  <div style={{...S.section,marginBottom:16}}>
    <h3 style={{...S.title,fontSize:14}}>{title}</h3>
    {sub && <p style={S.sub}>{sub}</p>}
    {children}
  </div>
);

// ================================================================ PLAYBOOKS
export function PlaybookPanel({ api }) {
  const [cases,setCases]=useState([]); const [cid,setCid]=useState('');
  const [books,setBooks]=useState([]); const [sel,setSel]=useState('');
  const [target,setTarget]=useState(''); const [run,setRun]=useState(null);
  const [custom,setCustom]=useState(''); const [msg,setMsg]=useState(''); const [err,setErr]=useState('');
  useEffect(()=>{api.get('/cases').then(r=>setCases(r.data)).catch(()=>{});api.get('/playbooks').then(r=>setBooks(r.data)).catch(()=>{});},[api]);
  const doRun=async()=>{ if(!sel||!target)return; setErr(''); setRun(null);
    try{const r=await api.post('/playbooks/run',{name:sel,target,case_id:cid?+cid:undefined});setRun(r.data);}
    catch(e){setErr(e.response?.data?.error||e.message);} };
  const del=async(n)=>{try{await api.delete(`/playbooks/${encodeURIComponent(n)}`);setBooks(b=>b.filter(x=>x.name!==n));}catch(e){setErr(e.message);}};
  const save=async()=>{ let steps; try{steps=JSON.parse(custom);}catch{setErr('steps must be JSON array');return;}
    try{const r=await api.post('/playbooks',{name:custom.name||'custom-'+Date.now(),steps});setBooks(b=>[...b,r.data]);setCustom('');setMsg('saved');setTimeout(()=>setMsg(''),2000);}catch(e){setErr(e.response?.data?.error||e.message);} };
  return (
    <div style={S.section}>
      <h2 style={S.title}>Investigation Playbooks</h2>
      <p style={S.sub}>Auto-pivot chains: a named multi-step investigation re-run on any target, emitting per-step evidence and graph edges. Steps are <code>module:function</code> references resolved lazily and executed in order.</p>
      <div style={S.row}>
        <select style={S.select} value={sel} onChange={e=>setSel(e.target.value)}>
          <option value="">select playbook…</option>{books.map(b=><option key={b.name} value={b.name}>{b.name}</option>)}
        </select>
        <select style={S.select} value={cid} onChange={e=>setCid(e.target.value)}>
          <option value="">no case</option>{cases.map(c=><option key={c.id} value={c.id}>{c.case_number} — {c.name}</option>)}
        </select>
        <input style={{...S.input,flex:1,minWidth:180}} placeholder="target (domain / ip / person / address)" value={target} onChange={e=>setTarget(e.target.value)} onKeyDown={e=>e.key==='Enter'&&doRun()}/>
        <button style={S.btn} onClick={doRun} disabled={!sel||!target}>Run chain</button>
      </div>
      <Err e={err}/>{msg&&<div style={{color:'#2ecc71',fontSize:12,marginTop:8}}>{msg}</div>}
      <div style={{marginTop:14}}>{books.map(b=>(
        <div key={b.name} style={S.card}>
          <div style={{...S.row,justifyContent:'space-between'}}>
            <strong style={{color:'#e6edf3',fontSize:14}}>{b.name}</strong>
            <button style={{...S.btn,background:'#e74c3c',padding:'4px 10px',fontSize:11}} onClick={()=>del(b.name)}>delete</button>
          </div>
          {b.description&&<div style={{color:'#8b949e',fontSize:12,marginTop:2}}>{b.description}</div>}
          <div style={{marginTop:6}}>{(b.steps||[]).map((st,i)=><span key={i} style={S.tag}>{i+1}. {st.module}</span>)}</div>
        </div>))}
      </div>
      {run&&(
        <div style={{...S.card,border:'1px solid #2ecc71'}}>
          <div style={S.label}>Run result — {run.playbook} → {run.target} ({run.elapsed}s)</div>
          {(run.steps||[]).map((st,i)=>(
            <div key={i} style={{...S.row,marginBottom:6,justifyContent:'space-between'}}>
              <span style={{...S.mono,color:'#e6edf3'}}>{i+1}. {st.module}</span>
              <span style={{...S.pill,background:st.status==='ok'?'#2ecc71':'#e74c3c'}}>{st.status}</span>
              <span style={{color:'#8b949e',fontSize:11,flex:1}}>{typeof st.summary==='string'?st.summary.slice(0,120):JSON.stringify(st.summary).slice(0,120)}</span>
            </div>))}
        </div>)}
      <div style={{marginTop:16}}>
        <div style={S.label}>Custom playbook (JSON steps array)</div>
        <input style={S.input} placeholder='[{"module":"infra.infra:pivot_ip"}, {"module":"crypto.crypto:address_overview"}]' value={custom} onChange={e=>setCustom(e.target.value)}/>
        <button style={{...S.btn,marginTop:8}} onClick={save}>Save custom</button>
      </div>
    </div>
  );
}

// ================================================================ GLOBAL CORPORATE
export function GlobalCorpPanel({ api }) {
  const [q,setQ]=useState(''); const [res,setRes]=useState(null);
  const [lei,setLei]=useState(''); const [rel,setRel]=useState(null);
  const [vat,setVat]=useState(''); const [vatRes,setVatRes]=useState(null);
  const [ch,setCh]=useState(''); const [chRes,setChRes]=useState(null);
  const [err,setErr]=useState('');
  const search=async()=>{if(!q)return;setErr('');try{const r=await api.get(`/worldcorp/gleif?q=${encodeURIComponent(q)}`);setRes(r.data);}catch(e){setErr(e.response?.data?.error||e.message);}};
  const rels=async()=>{if(!lei)return;setErr('');try{const r=await api.get(`/worldcorp/relationships/${encodeURIComponent(lei)}`);setRel(r.data);}catch(e){setErr(e.response?.data?.error||e.message);}};
  const doVat=async()=>{if(!vat)return;setErr('');try{const r=await api.get(`/worldcorp/vat?vat=${encodeURIComponent(vat)}`);setVatRes(r.data);}catch(e){setErr(e.response?.data?.error||e.message);}};
  const doCh=async()=>{if(!ch)return;setErr('');try{const r=await api.get(`/worldcorp/ch?q=${encodeURIComponent(ch)}`);setChRes(r.data);}catch(e){setErr(e.response?.data?.error||e.message);}};
  return (
    <div style={S.section}>
      <h2 style={S.title}>Global Corporate Registry</h2>
      <p style={S.sub}>GLEIF LEI records (keyless), EU VAT validation via VIES, and UK Companies House (optional key). Free international corporate identity — subsidiaries, jurisdictions, HQ.</p>
      <Section title="GLEIF — LEI search by legal name">
        <div style={S.row}>
          <input style={{...S.input,flex:1,minWidth:180}} placeholder="legal name (e.g. Deutsche Bank)" value={q} onChange={e=>setQ(e.target.value)} onKeyDown={e=>e.key==='Enter'&&search()}/>
          <button style={S.btn} onClick={search}>Search GLEIF</button>
        </div>
        {res?.results?.length>0&&(
          <div style={{marginTop:10}}>{res.results.map((r,i)=>(
            <div key={i} style={S.card}>
              <div style={{...S.row,justifyContent:'space-between'}}>
                <strong style={{color:'#e6edf3'}}>{r.name}</strong><St s={r.status}/>
              </div>
              <KV k="LEI" v={<span style={S.mono}>{r.lei}</span>}/>
              <KV k="legal / HQ" v={`${r.legal_country||'—'} · ${r.legal_city||''}  /  ${r.hq_country||'—'} · ${r.hq_city||''}`}/>
              <KV k="jurisdiction / category" v={`${r.jurisdiction||'—'} · ${r.category||''}`}/>
              <div style={{marginTop:6}}><button style={{...S.btn,background:'#21262d',padding:'4px 10px',fontSize:11}} onClick={()=>{setLei(r.lei);setRel(null);}}>view structure</button></div>
            </div>))}
          </div>)}
        {res&&res.count===0&&<div style={{color:'#8b949e',fontSize:12,marginTop:8}}>No GLEIF records.</div>}
      </Section>
      <Section title="Ownership structure — parents & direct children">
        <div style={S.row}>
          <input style={{...S.input,flex:1,minWidth:180}} placeholder="LEI (12-20 chars)" value={lei} onChange={e=>setLei(e.target.value)} onKeyDown={e=>e.key==='Enter'&&rels()}/>
          <button style={S.btn} onClick={rels}>Resolve</button>
        </div>
        {rel&&(
          <div style={{marginTop:10}}>
            {(rel.parents||[]).map((p,i)=><div key={'p'+i} style={S.card}><KV k="parent" v={p.name}/><KV k="LEI" v={<span style={S.mono}>{p.lei}</span>}/><KV k="country" v={p.country}/></div>)}
            {(rel.children||[]).map((p,i)=><div key={'c'+i} style={S.card}><KV k="child" v={p.name}/><KV k="LEI" v={<span style={S.mono}>{p.lei}</span>}/><KV k="country" v={p.country}/></div>)}
            {!(rel.parents||[]).length&&!(rel.children||[]).length&&<div style={{color:'#8b949e',fontSize:12}}>No direct parent/child links resolved.</div>}
          </div>)}
      </Section>
      <Section title="EU VAT (VIES) validation">
        <div style={S.row}>
          <input style={{...S.input,flex:1,minWidth:180}} placeholder="VAT number (e.g. LU26375245)" value={vat} onChange={e=>setVat(e.target.value)} onKeyDown={e=>e.key==='Enter'&&doVat()}/>
          <button style={S.btn} onClick={doVat}>Validate</button>
        </div>
        {vatRes&&(<div style={{marginTop:10,marginBottom:0,...S.card}}>
          <KV k="valid" v={vatRes.valid?'yes':'no'}/><KV k="name" v={vatRes.name}/><KV k="address" v={vatRes.address}/>
        </div>)}
      </Section>
      <Section title="UK Companies House (needs CH_API_KEY)">
        <div style={S.row}>
          <input style={{...S.input,flex:1,minWidth:180}} placeholder="company name" value={ch} onChange={e=>setCh(e.target.value)} onKeyDown={e=>e.key==='Enter'&&doCh()}/>
          <button style={S.btn} onClick={doCh}>Search</button>
        </div>
        {chRes&&<pre style={S.pre}>{JSON.stringify(chRes,null,2)}</pre>}
      </Section>
      <Err e={err}/>
    </div>
  );
}

// ================================================================ WORLD RISK
export function WorldRiskPanel({ api }) {
  const [q,setQ]=useState(''); const [news,setNews]=useState(null);
  const [cc,setCc]=useState('DE'); const [prof,setProf]=useState(null); const [card,setCard]=useState(null);
  const [overlay,setOverlay]=useState(''); const [ovRes,setOvRes]=useState(null);
  const [err,setErr]=useState('');
  const gdelt=async()=>{if(!q)return;setErr('');try{const r=await api.get(`/risk/gdelt?q=${encodeURIComponent(q)}`);setNews(r.data);}catch(e){setErr(e.response?.data?.error||e.message);}};
  const country=async()=>{if(!cc)return;setErr('');try{const[a,b]=await Promise.all([api.get(`/risk/country?c=${encodeURIComponent(cc)}`),api.get(`/risk/jurisdiction?c=${encodeURIComponent(cc)}`)]);setProf(a.data);setCard(b.data);}catch(e){setErr(e.response?.data?.error||e.message);}};
  const ov=async()=>{if(!overlay)return;setErr('');try{const r=await api.post('/risk/overlay',{countries:overlay});setOvRes(r.data);}catch(e){setErr(e.response?.data?.error||e.message);}};
  return (
    <div style={S.section}>
      <h2 style={S.title}>World Risk & Jurisdiction</h2>
      <p style={S.sub}>GDELT global news events, World Bank country indicators, jurisdiction legal cards, and sanctions/export-control overlays.</p>
      <Section title="GDELT — global news event search">
        <div style={S.row}>
          <input style={{...S.input,flex:1,minWidth:180}} placeholder="query (e.g. ukraine, strait of hormuz)" value={q} onChange={e=>setQ(e.target.value)} onKeyDown={e=>e.key==='Enter'&&gdelt()}/>
          <button style={S.btn} onClick={gdelt}>Search GDELT</button>
        </div>
        {news?.articles?.length>0&&(
          <div style={{marginTop:10}}>{news.articles.map((a,i)=>(
            <div key={i} style={S.card}>
              <a href={a.url} target="_blank" rel="noreferrer" style={{color:'#58a6ff',fontSize:13,fontWeight:600}}>{a.title}</a>
              <KV k="source" v={`${a.domain||''} · ${a.sourcecountry||''}`}/><KV k="seen" v={a.seendate}/>
            </div>))}
          </div>)}
        {news&&news.status&&news.status!=='ok'&&<div style={{color:'#e67e22',fontSize:12,marginTop:8}}>{news.status}: {news.error||''}</div>}
      </Section>
      <Section title="Country profile & jurisdiction legal card">
        <div style={S.row}>
          <select style={S.select} value={cc} onChange={e=>setCc(e.target.value)}>
            {['US','GB','DE','FR','NL','IE','ES','IT','NO','CH','UA','RU','TR','AE','SA','IL','IN','CN','JP','KR','SG','AU','BR','MX','CA','ZA','NG','EG'].map(c=><option key={c}>{c}</option>)}
          </select>
          <button style={S.btn} onClick={country}>Load</button>
        </div>
        {prof&&(
          <div style={{marginTop:10}}>
            <div style={S.label}>Indicators (World Bank)</div>
            {Object.entries(prof.indicators||{}).map(([k,v])=><KV key={k} k={k} v={typeof v==='object'?JSON.stringify(v):v}/>)}
            <div style={{...S.label,marginTop:8}}>Risk snapshot</div>
            {Object.entries(prof.risk||{}).map(([k,v])=><KV key={k} k={k} v={v}/>)}
          </div>)}
        {card&&(
          <div style={{...S.card,marginTop:12,border:'1px solid #e67e22'}}>
            <div style={S.label}>Jurisdiction card — {card.country}</div>
            {['privacy_law','enforcement_authority','scraping_posture','pi_licensing','data_localization','lawful_access_note'].map(k=><KV key={k} k={k.replace(/_/g,' ')} v={card[k]}/>)}
            {card.disclaimer&&<div style={{color:'#8b949e',fontSize:11,marginTop:6,fontStyle:'italic'}}>{card.disclaimer}</div>}
          </div>)}
      </Section>
      <Section title="Sanctions / export-control overlay">
        <div style={S.row}>
          <input style={{...S.input,flex:1,minWidth:180}} placeholder="comma countries (e.g. RU, IR, CN)" value={overlay} onChange={e=>setOverlay(e.target.value)} onKeyDown={e=>e.key==='Enter'&&ov()}/>
          <button style={S.btn} onClick={ov}>Check</button>
        </div>
        {ovRes&&<pre style={S.pre}>{JSON.stringify(ovRes,null,2)}</pre>}
      </Section>
      <Err e={err}/>
    </div>
  );
}

// ================================================================ GEO EXTRA
export function GeoExtraPanel({ api }) {
  const [lat,setLat]=useState('51.5074'); const [lon,setLon]=useState('-0.1278'); const [rad,setRad]=useState('300');
  const [b,setB]=useState(null); const [p,setP]=useState(null); const [f,setF]=useState(null);
  const [mp,setMp]=useState(null);
  const [cc,setCc]=useState('us'); const [zip,setZip]=useState(''); const [zr,setZr]=useState(null);
  const [err,setErr]=useState('');
  const q=`lat=${lat}&lon=${lon}&radius=${rad}`;
  const load=async()=>{setErr('');try{const[B,P,F]=await Promise.all([api.get(`/geoext/buildings?${q}&cap=200`),api.get(`/geoext/pois?${q}&cap=200`),api.get(`/geoext/footprints?${q}&cap=120`)]);setB(B.data);setP(P.data);setF(F.data);}catch(e){setErr(e.response?.data?.error||e.message);}};
  const mapillary=async()=>{setErr('');try{const r=await api.get(`/geoext/mapillary?lat=${lat}&lon=${lon}`);setMp(r.data);}catch(e){setErr(e.response?.data?.error||e.message);}};
  const doZip=async()=>{if(!zip)return;setErr('');try{const r=await api.get(`/geoext/zip?cc=${cc}&zip=${zip}`);setZr(r.data);}catch(e){setErr(e.response?.data?.error||e.message);}};
  const [dl,setDl]=useState(false);
  useEffect(()=>{if(!f?.features?.length)return;setDl(true);const t=setTimeout(()=>setDl(false),600);return()=>clearTimeout(t);},[f]);
  return (
    <div style={S.section}>
      <h2 style={S.title}>Geo Extra — Buildings, POIs & Imagery</h2>
      <p style={S.sub}>OSM Overpass building footprints + POIs at any coordinate, GeoJSON for the map, optional street-level imagery, and postal/ZIP geocoding.</p>
      <div style={S.row}>
        <input style={{...S.input,width:110}} value={lat} onChange={e=>setLat(e.target.value)} placeholder="lat"/>
        <input style={{...S.input,width:110}} value={lon} onChange={e=>setLon(e.target.value)} placeholder="lon"/>
        <input style={{...S.input,width:90}} value={rad} onChange={e=>setRad(e.target.value)} placeholder="radius"/>
        <button style={S.btn} onClick={load}>Load area</button>
        <button style={{...S.btn,background:'#21262d'}} onClick={mapillary}>Street imagery</button>
      </div>
      <Err e={err}/>
      {(b||p)&&(
        <div style={{marginTop:12}}>
          <KV k="buildings" v={b?.count}/><KV k="POIs" v={p?.count}/><KV k="geojson features" v={f?.features?.length||0}/>
        </div>)}
      {f?.features?.length>0&&(
        <div style={{marginTop:12}}>
          <div style={S.label}>Building footprints (GeoJSON)</div>
          <svg viewBox="0 0 440 260" style={{width:'100%',maxWidth:520,background:'#010409',border:'1px solid #30363d',borderRadius:8}}>
            {(()=>{ const feats=f.features.filter(ft=>ft.geometry);
              const rings=feats.map(ft=>ft.geometry.type==='Polygon'?ft.geometry.coordinates[0]:(ft.geometry.type==='MultiPolygon'?ft.geometry.coordinates[0][0]:null)).filter(Boolean);
              if(!rings.length)return null;
              const all=rings.flat(); const xs=all.map(c=>c[0]),ys=all.map(c=>c[1]);
              const minx=Math.min(...xs),maxx=Math.max(...xs),miny=Math.min(...ys),maxy=Math.max(...ys);
              const sx=x=>20+((x-minx)/((maxx-minx)||1))*400, sy=y=>240-((y-miny)/((maxy-miny)||1))*220;
              return <g>{rings.map((ring,i)=><polygon key={i} points={ring.map(c=>`${sx(c[0])},${sy(c[1])}`).join(' ')} fill="rgba(31,111,235,0.25)" stroke="#1f6feb" strokeWidth="1"/>)}</g>;
            })()}
          </svg>
          {dl&&<div style={{color:'#8b949e',fontSize:11,marginTop:4}}>live OSM data · {f.features.length} footprints</div>}
        </div>)}
      {p?.pois?.length>0&&(
        <div style={{marginTop:12}}>
          <div style={S.label}>Points of interest</div>
          {p.pois.slice(0,20).map((x,i)=><span key={i} style={S.tag}>{x.tags?.amenity||x.tags?.shop||x.tags?.tourism||x.tags?.office||'poi'}{x.tags?.name?` · ${x.tags.name}`:''}</span>)}
        </div>)}
      {mp&&<div style={{marginTop:12}}><div style={S.label}>Street-level imagery</div><pre style={S.pre}>{JSON.stringify(mp,null,2)}</pre></div>}
      <Section title="Postal / ZIP geocode (zippopotam.us)">
        <div style={S.row}>
          <select style={S.select} value={cc} onChange={e=>setCc(e.target.value)}>{['us','gb','de','fr','in','br','ca','au','jp'].map(c=><option key={c}>{c}</option>)}</select>
          <input style={{...S.input,flex:1,minWidth:120}} placeholder="postal code" value={zip} onChange={e=>setZip(e.target.value)} onKeyDown={e=>e.key==='Enter'&&doZip()}/>
          <button style={S.btn} onClick={doZip}>Geocode</button>
        </div>
        {zr&&(<div style={{marginTop:10,...S.card}}>
          <KV k="place" v={zr.place}/><KV k="state" v={zr.state}/><KV k="coords" v={`${zr.lat}, ${zr.lon}`}/>
        </div>)}
      </Section>
    </div>
  );
}

// ================================================================ AI BRIEF
export function AiBriefPanel({ api }) {
  const [cases,setCases]=useState([]); const [cid,setCid]=useState('');
  const [digest,setDigest]=useState(null); const [narr,setNarr]=useState(null);
  const [busy,setBusy]=useState(false); const [err,setErr]=useState('');
  useEffect(()=>{api.get('/cases').then(r=>setCases(r.data)).catch(()=>{});},[api]);
  const load=useCallback(async()=>{if(!cid)return;setErr('');try{const r=await api.get(`/narrative/digest/${cid}`);setDigest(r.data);}catch(e){setErr(e.response?.data?.error||e.message);}},[api,cid]);
  useEffect(()=>{load();},[load]);
  const gen=async()=>{if(!cid)return;setBusy(true);setErr('');try{const r=await api.post('/narrative/generate',{case_id:+cid});setNarr(r.data);}catch(e){setErr(e.response?.data?.error||e.message);}setBusy(false);};
  return (
    <div style={S.section}>
      <h2 style={S.title}>AI Evidence Brief</h2>
      <p style={S.sub}>Deterministic, SHA-256-cited case narrative assembled from the evidence graph (Groq/Gemini when a key is present). Every statement traces to an artifact hash.</p>
      <div style={S.row}>
        <select style={S.select} value={cid} onChange={e=>setCid(e.target.value)}>
          <option value="">select case…</option>{cases.map(c=><option key={c.id} value={c.id}>{c.case_number} — {c.name}</option>)}
        </select>
        <button style={S.btn} onClick={gen} disabled={!cid||busy}>{busy?'Generating…':'Generate brief'}</button>
      </div>
      <Err e={err}/>
      {digest&&(
        <div style={{marginTop:14}}>
          <div style={S.label}>Case digest</div>
          <KV k="entities" v={Object.keys(digest.entities||{}).length}/>
          <KV k="artifacts" v={Object.keys(digest.artifacts||{}).length}/>
          <KV k="alerts" v={digest.alerts?.length||0}/>
        </div>)}
      {narr&&(
          <div style={{...S.card,marginTop:14,border:'1px solid #1f6feb'}}>
            <div style={{...S.row,justifyContent:'space-between'}}>
            <div style={S.label}>Narrative — engine {narr.engine}</div>
            {narr.citations?.length>0&&<span style={{color:'#8b949e',fontSize:11}}>{narr.citations.length} cited hashes</span>}
          </div>
          <pre style={S.pre}>{narr.narrative}</pre>
        </div>)}
    </div>
  );
}
// ================================================================ TRACKERS
export function TrackersPanel({ api }) {
  const [reg,setReg]=useState([]); const [rows,setRows]=useState([]);
  const [kind,setKind]=useState('dns_watch'); const [target,setTarget]=useState(''); const [cid,setCid]=useState('');
  const [alerts,setAlerts]=useState([]); const [err,setErr]=useState(''); const [busy,setBusy]=useState('');
  const load=useCallback(()=>{
    api.get('/trackers').then(r=>{setReg(r.data.registry||[]);setRows(r.data.trackers||[]);}).catch(e=>setErr(e.message));
    api.get('/trackers/alerts').then(r=>setAlerts(r.data.alerts||[])).catch(()=>{});
  },[api]);
  useEffect(()=>{load();},[load]);
  const reg1=async()=>{
    if(!target.trim())return; setBusy('reg'); setErr('');
    try{await api.post('/trackers',{kind,target,case_id:cid?+cid:undefined});setTarget('');load();}
    catch(e){setErr(e.response?.data?.error||e.message);} setBusy('');
  };
  const check=async(id)=>{setBusy('c'+id);try{await api.post(`/trackers/${id}/check`);load();}catch(e){setErr(e.response?.data?.error||e.message);}setBusy('');};
  const runDue=async()=>{setBusy('due');try{await api.post('/trackers/run_due',{limit:15});load();}catch(e){setErr(e.response?.data?.error||e.message);}setBusy('');};
  const del=async(id)=>{try{await api.delete(`/trackers/${id}`);load();}catch(e){setErr(e.response?.data?.error||e.message);}};
  const hint=(reg.find(r=>r.kind===kind)||{}).target_hint||'';
  const sevBg=s=>({'critical':'#c0392b',high:'#e74c3c',medium:'#e67e22',low:'#e6ae33',info:'#7f8c8d'}[s]||'#7f8c8d');
  return (
    <div style={S.section}>
      <h2 style={S.title}>Subject Trackers</h2>
      <p style={S.sub}>Long-lived change watchers: every check fingerprints the subject (DNS, registrar, ports, content, wallet, sightings, breaches, LEI, news, channel, sanctions), diffs against the last fingerprint and raises typed alerts. Daemon re-checks by interval; alerts land in the shared pipeline.</p>
      <div style={S.row}>
        <select style={S.select} value={kind} onChange={e=>setKind(e.target.value)}>
          {reg.map(r=><option key={r.kind} value={r.kind}>{r.kind}</option>)}
        </select>
        <span style={{...S.tag,minWidth:210,textAlign:'center'}}>{(reg.find(r=>r.kind===kind)||{}).label}</span>
        <input style={{...S.input,flex:1,minWidth:160}} placeholder={`target (${hint || 'watch target'})`} value={target} onChange={e=>setTarget(e.target.value)} onKeyDown={e=>e.key==='Enter'&&reg1()}/>
        <input style={{...S.input,width:90}} placeholder="case id" value={cid} onChange={e=>setCid(e.target.value)}/>
        <button style={S.btn} onClick={reg1} disabled={busy==='reg'||!target.trim()}>{busy==='reg'?'Registering…':'Watch target'}</button>
        <button style={{...S.btn,background:'#27ae60'}} onClick={runDue} disabled={busy==='due'}>{busy==='due'?'Checking…':'Run all due'}</button>
      </div>
      <Err e={err}/>
      <div style={{marginTop:14}}>
        {rows.length===0&&<div style={{color:'#8b949e',fontSize:12}}>No trackers yet — register one above. Suggested first watches: a domain (dns_watch), the escape wallet (crypto_watch), a key person (person_exposure).</div>}
        {rows.map(t=>(
          <div key={t.id} style={S.card}>
            <div style={{...S.row,justifyContent:'space-between'}}>
              <div style={{...S.row,flex:1}}>
                <strong style={{color:'#e6edf3',fontSize:13}}>{t.kind}</strong>
                <span style={{...S.pill,background:t.last_status==='ok'?'#2ecc71':(t.last_status==='blocked'?'#e67e22':(t.fails>=3?'#c0392b':'#7f8c8d'))}}>{t.last_status||t.fails>=3?'fails:'+t.fails:'fresh'}</span>
                <span style={S.mono}>{t.target}</span>
                {t.case_id?<span style={S.tag}>case {t.case_id}</span>:null}
                <span style={{color:'#8b949e',fontSize:11}}>{t.label}</span>
              </div>
              <div style={S.row}>
                <span style={{color:'#8b949e',fontSize:11}}>every {t.interval_min}m · last {t.last_check?t.last_check.slice(0,16).replace('T',' '):'—'}</span>
                <button style={{...S.btn,background:'#27ae60',padding:'4px 10px',fontSize:11}} onClick={()=>check(t.id)} disabled={busy==='c'+t.id}>{busy==='c'+t.id?'…':'check now'}</button>
                <button style={{...S.btn,background:'#e74c3c',padding:'4px 10px',fontSize:11}} onClick={()=>del(t.id)}>delete</button>
              </div>
            </div>
            {t.last_error&&<div style={{color:'#e67e22',fontSize:11,marginTop:4}}>last error: {t.last_error}</div>}
            {t.state_summary&&Object.keys(t.state_summary).length>0&&(
              <details style={{marginTop:6}}>
                <summary style={{cursor:'pointer',color:'#8b949e',fontSize:11}}>last fingerprint</summary>
                <pre style={{...S.pre,marginTop:6}}>{JSON.stringify(t.state_summary,null,2)}</pre>
              </details>)}
          </div>))}
      </div>
      <div style={{marginTop:18}}>
        <div style={S.label}>Tracker alerts ({alerts.length})</div>
        {alerts.map(a=>(
          <div key={a.id} style={{...S.row,marginBottom:6,alignItems:'flex-start'}}>
            <span style={{...S.pill,background:sevBg(a.severity)}}>{a.severity}</span>
            <div style={{flex:1}}>
              <div style={{color:'#e6edf3',fontSize:12}}>{a.message.slice(0,180)}</div>
              <div style={{color:'#8b949e',fontSize:10}}>{(a.ts||'').slice(0,19).replace('T',' ')}{a.case_id?` · case ${a.case_id}`:''}</div>
            </div>
          </div>))}
        {alerts.length===0&&<div style={{color:'#8b949e',fontSize:12}}>No tracker alerts yet. Alerts appear when a fingerprint changes (e.g., new ALPR sighting, balance move, sanctions match).</div>}
      </div>
    </div>
  );
}
