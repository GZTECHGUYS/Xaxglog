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
  pre:{fontFamily:'ui-monospace,Menlo,monospace',fontSize:11,color:'#8b949e',whiteSpace:'pre-wrap',maxHeight:260,overflowY:'auto',background:'#010409',padding:10,borderRadius:6,margin:0},

};
const S = { ...LEGACY_S, ...CYBER_S };
const Err = ({e}) => e ? <div style={{...S.card,border:'1px solid #e74c3c',background:'#2a1a1a',color:'#e74c3c',fontSize:13}}>{typeof e==='string'?e:JSON.stringify(e)}</div> : null;
const KV = ({k,v}) => <div><span style={{color:'#8b949e'}}>{k}: </span><span style={{color:'#e6edf3'}}>{v??'—'}</span></div>;

// Download an auth-gated endpoint via the authed axios instance: raw <a href>
// links cannot attach the Bearer token and always end in 401.
const dl = async (api, path, filename) => {
  try {
    const r = await api.get(path, { responseType: 'blob' });
    const url = URL.createObjectURL(r.data);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 3000);
  } catch (e) {
    console.error('download failed', e);
    alert('download failed: ' + (e.message || 'error'));
  }
};

// ---------------------------------------------------------------- GEOINT MAP
export function GeoPanel({ api }) {
  const [cases,setCases]=useState([]); const [cid,setCid]=useState('');
  const [place,setPlace]=useState(''); const [geoRes,setGeoRes]=useState(null);
  const [pts,setPts]=useState(null); const [q,setQ]=useState({lat:'',lon:'',radius:1000}); const [near,setNear]=useState(null);
  const [msg,setMsg]=useState(''); const [err,setErr]=useState('');
  useEffect(()=>{api.get('/cases').then(r=>setCases(r.data)).catch(()=>{});},[api]);
  const loadPts=useCallback(async()=>{ if(!cid)return; try{const r=await api.get(`/geo/case/${cid}`);setPts(r.data);}catch(e){setErr(e.message);} },[api,cid]);
  useEffect(()=>{loadPts();},[loadPts]);
  const geo=async()=>{if(!place)return;setErr('');try{const r=await api.get(`/geo/geocode?place=${encodeURIComponent(place)}`);setGeoRes(r.data);}catch(e){setErr(e.message);}};
  const attach=async()=>{if(!geoRes?.results?.length||!cid)return;try{await api.post('/geo/geocode_case',{place:geoRes.results[0].name,case_id:+cid});setMsg('point attached to case');setTimeout(()=>setMsg(''),2500);}catch(e){setErr(e.message);}};
  const findNear=async()=>{if(!cid||!q.lat)return;setErr('');try{const r=await api.get(`/geo/within?case_id=${cid}&lat=${q.lat}&lon=${q.lon}&radius=${q.radius}`);setNear(r.data);}catch(e){setErr(e.message);}};
  return (
    <div style={S.section}>
      <h2 style={S.title}>GEOINT Map</h2>
      <p style={S.sub}>Geocode places, attach coordinates to a case, then plot & radius-query every geo point (IPs, places, ALPR, cameras).</p>
      <div style={S.row}>
        <select style={S.select} value={cid} onChange={e=>setCid(e.target.value)}>
          <option value="">select case…</option>{cases.map(c=><option key={c.id} value={c.id}>{c.case_number} — {c.name}</option>)}
        </select>
        <input style={{...S.input,flex:1,minWidth:160}} placeholder="place to geocode" value={place} onChange={e=>setPlace(e.target.value)} onKeyDown={e=>e.key==='Enter'&&geo()}/>
        <button style={S.btn} onClick={geo}>Geocode</button>
        {geoRes?.results?.[0] && <button style={{...S.btn,background:'#2ecc71'}} onClick={attach}>Attach to case</button>}
      </div>
      <Err e={err}/>{msg&&<div style={{color:'#2ecc71',fontSize:12,marginTop:8}}>{msg}</div>}
      {geoRes?.results?.length>0&&(
        <div style={{marginTop:12}}>{geoRes.results.map((r,i)=>(
          <div key={i} style={S.card}><KV k="place" v={r.name}/><KV k="lat" v={r.lat}/><KV k="lon" v={r.lon}/></div>))}</div>)}
      {pts&&(
        <div style={{marginTop:16}}>
          <div style={S.label}>Case map points — {pts.count}</div>
          {pts.count>0&&(
            <svg viewBox="0 0 440 300" style={{width:'100%',maxWidth:520,background:'#010409',border:'1px solid #30363d',borderRadius:8}}>
              {(()=>{
                const lats=pts.points.map(p=>p.lat),lons=pts.points.map(p=>p.lon);
                const minla=Math.min(...lats),maxla=Math.max(...lats),minlo=Math.min(...lons),maxlo=Math.max(...lons);
                const sx=(lo)=>30+((lo-minlo)/((maxlo-minlo)||1))*380;
                const sy=(la)=>270-((la-minla)/((maxla-minla)||1))*240;
                return <g>{pts.points.map((p,i)=>(<g key={i}><circle cx={sx(p.lon)} cy={sy(p.lat)} r={4} fill="#1f6feb"/><text x={sx(p.lon)+6} y={sy(p.lat)+3} fill="#8b949e" fontSize={7}>{String(p.type)}</text></g>))}</g>;
              })()}
            </svg>)}
          <div style={{...S.row,marginTop:10}}>
            <input style={{...S.input,width:90}} placeholder="lat" value={q.lat} onChange={e=>setQ({...q,lat:e.target.value})}/>
            <input style={{...S.input,width:90}} placeholder="lon" value={q.lon} onChange={e=>setQ({...q,lon:e.target.value})}/>
            <input style={{...S.input,width:110}} placeholder="radius m" value={q.radius} onChange={e=>setQ({...q,radius:e.target.value})}/>
            <button style={{...S.btn,background:'#e67e22'}} onClick={findNear}>Within radius</button>
            <button style={{...S.btn,background:'#30363d'}} onClick={()=>dl(`geo/export/${cid}.geojson`,`case-${cid}.geojson`)}>GeoJSON</button>
            <button style={{...S.btn,background:'#30363d'}} onClick={()=>dl(`geo/export/${cid}.kml`,`case-${cid}.kml`)}>KML</button>
          </div>
          {near&&<div style={{marginTop:10}}><div style={S.label}>{near.count} within {near.radius_m}m</div>
            {near.results.map((r,i)=><div key={i} style={{...S.card}}><span style={S.tag}>{r.type}</span><span style={{...S.mono,color:'#e6edf3'}}>{r.value}</span><span style={{color:'#8b949e',fontSize:12}}> — {r.distance_m}m</span></div>)}</div>}
        </div>)}
    </div>
  );
}

// ---------------------------------------------------------------- VEHICLE
export function VehiclePanel({ api }) {
  const [cases,setCases]=useState([]); const [cid,setCid]=useState('');
  const [vin,setVin]=useState(''); const [vinRes,setVinRes]=useState(null);
  const [plate,setPlate]=useState(''); const [jur,setJur]=useState('US'); const [auth,setAuth]=useState('');
  const [revRes,setRevRes]=useState(null); const [alpr,setAlpr]=useState({plate:'',lat:'',lon:'',camera_id:''});
  const [timeline,setTimeline]=useState(null); const [err,setErr]=useState(''); const [msg,setMsg]=useState('');
  const [endpoint,setEndpoint]=useState('');
  useEffect(()=>{api.get('/cases').then(r=>setCases(r.data)).catch(()=>{});},[api]);
  const dec=async()=>{if(!vin)return;setErr('');try{const r=await api.post('/vehicle/vin',{vin,case_id:cid?+cid:null});setVinRes(r.data);}catch(e){setErr(e.response?.data?.error||e.message);}};
  const rev=async()=>{if(!plate)return;setErr('');try{const r=await api.post('/vehicle/reverse_plate',{plate,jurisdiction:jur,authority_ref:auth,case_id:cid?+cid:null});setRevRes(r.data);}catch(e){setRevRes(e.response?.data||{error:e.message});}};
  const ingest=async()=>{if(!alpr.plate)return;setErr('');try{await api.post('/vehicle/alpr',{...alpr,case_id:cid?+cid:null});setMsg('ALPR sighting stored (custody)');setTimeout(()=>setMsg(''),2500);}catch(e){setErr(e.message);}};
  const tl=async()=>{if(!plate)return;try{const r=await api.get(`/vehicle/timeline?plate=${encodeURIComponent(plate)}${cid?`&case_id=${cid}`:''}`);setTimeline(r.data);}catch(e){setErr(e.message);}};
  return (
    <div style={S.section}>
      <h2 style={S.title}>Vehicle Intelligence</h2>
      <p style={S.sub}>VIN decode + recalls (NHTSA, free), plate decode, authority-gated reverse-plate/registration (gateway configured later), ALPR sightings into evidence custody.</p>
      <div style={S.row}>
        <select style={S.select} value={cid} onChange={e=>setCid(e.target.value)}><option value="">select case…</option>{cases.map(c=><option key={c.id} value={c.id}>{c.case_number}</option>)}</select>
      </div>
      {/* VIN */}
      <div style={{marginTop:14}}>
        <div style={S.label}>VIN decode + recalls</div>
        <div style={S.row}>
          <input style={{...S.input,flex:1,minWidth:180}} placeholder="17-char VIN" value={vin} onChange={e=>setVin(e.target.value.toUpperCase())}/>
          <button style={S.btn} onClick={dec}>Decode</button>
        </div>
        {vinRes&&!vinRes.error&&(
          <div style={S.card}>
            <div style={{...S.row}}><span style={S.pill}>{vinRes.vehicle?.year} {vinRes.vehicle?.make} {vinRes.vehicle?.model}</span>
              <span style={{color:'#8b949e',fontSize:12}}>check digit: {vinRes.check_digit_valid?'valid':'—'}</span></div>
            <div style={{marginTop:6,fontSize:12,color:'#8b949e'}}>{vinRes.vehicle?.body_class} · {vinRes.vehicle?.plant_country}</div>
          </div>)}
        {vinRes?.error&&<Err e={vinRes.error}/>}
      </div>
      {/* Reverse plate */}
      <div style={{marginTop:16}}>
        <div style={S.label}>Reverse plate / registration (authority-gated)</div>
        <div style={S.row}>
          <input style={{...S.input,flex:1,minWidth:120}} placeholder="plate" value={plate} onChange={e=>setPlate(e.target.value.toUpperCase())}/>
          <select style={S.select} value={jur} onChange={e=>setJur(e.target.value)}><option>US</option><option>EU</option><option>UK</option></select>
          <input style={{...S.input,flex:1,minWidth:150}} placeholder="warrant / authority ref" value={auth} onChange={e=>setAuth(e.target.value)}/>
          <button style={{...S.btn,background:'#2ecc71'}} onClick={rev}>Request</button>
          <button style={{...S.btn,background:'#30363d'}} onClick={tl}>Timeline</button>
        </div>
        <Err e={err}/>{msg&&<div style={{color:'#2ecc71',fontSize:12,marginTop:6}}>{msg}</div>}
        {revRes&&(
          revRes.error?<Err e={revRes}/>:(
            <div style={{...S.card,marginTop:8,border:'1px solid #2ecc71'}}>
              <div style={{color:'#2ecc71',fontWeight:600,fontSize:13}}>{revRes.note}</div>
              {revRes.evidence&&<div style={{...S.mono,color:'#8b949e',marginTop:4}}>evidence: {revRes.evidence.hash}</div>}
              {revRes.delivery?.payload&&<pre style={S.pre}>{revRes.delivery.payload}</pre>}
            </div>))}
        {timeline&&<div style={{marginTop:8}}><div style={S.label}>{timeline.sightings} sighting(s)</div>
          {timeline.timeline.map((t,i)=><div key={i} style={{...S.card}}><span style={{...S.mono,color:'#e6edf3'}}>{t.plate}</span> <span style={{color:'#8b949e',fontSize:12}}>@{t.lat},{t.lon} {t.camera_id} — {t.observed_at}</span></div>)}</div>}
      </div>
      {/* ALPR intake */}
      <div style={{marginTop:16}}>
        <div style={S.label}>ALPR sighting intake (agency-collected → custody)</div>
        <div style={S.row}>
          <input style={{...S.input,width:110}} placeholder="plate" value={alpr.plate} onChange={e=>setAlpr({...alpr,plate:e.target.value.toUpperCase()})}/>
          <input style={{...S.input,width:80}} placeholder="lat" value={alpr.lat} onChange={e=>setAlpr({...alpr,lat:e.target.value})}/>
          <input style={{...S.input,width:80}} placeholder="lon" value={alpr.lon} onChange={e=>setAlpr({...alpr,lon:e.target.value})}/>
          <input style={{...S.input,width:110}} placeholder="camera id" value={alpr.camera_id} onChange={e=>setAlpr({...alpr,camera_id:e.target.value})}/>
          <button style={{...S.btn,background:'#e67e22'}} onClick={ingest}>Store</button>
        </div>
      </div>
      {/* endpoint config tab */}
      <details style={{marginTop:16}}>
        <summary style={{cursor:'pointer',color:'#58a6ff',fontWeight:600,fontSize:13}}>Vehicle data gateway endpoint (configure when provider ready)</summary>
        <div style={{...S.row,marginTop:8}}>
          <input style={{...S.input,flex:1}} placeholder="https://your-authorized-provider/api" value={endpoint} onChange={e=>setEndpoint(e.target.value)}/>
          <button style={{...S.btn,background:'#8957e5'}} onClick={()=>{setMsg('endpoint saved (set server-side VEHICLE_GATEWAY_ENDPOINT)');setTimeout(()=>setMsg(''),3000);}}>Save</button>
        </div>
        <div style={{color:'#8b949e',fontSize:11,marginTop:6}}>Configure server-side via config.VEHICLE_GATEWAY_ENDPOINT once the licensed provider is provisioned. Requests stay authority-gated either way.</div>
      </details>
    </div>
  );
}

// ---------------------------------------------------------------- CCTV
export function CctvPanel({ api }) {
  const [cases,setCases]=useState([]); const [cid,setCid]=useState('');
  const [q,setQ]=useState(''); const [found,setFound]=useState(null);
  const [reg,setReg]=useState({ip:'',port:80,label:'',lat:'',lon:''});
  const [cams,setCams]=useState([]); const [err,setErr]=useState(''); const [msg,setMsg]=useState('');
  useEffect(()=>{api.get('/cases').then(r=>setCases(r.data)).catch(()=>{});},[api]);
  const loadCams=useCallback(async()=>{try{const r=await api.get(`/cctv/cameras${cid?`?case_id=${cid}`:''}`);setCams(r.data);}catch(e){setErr(e.message);}},[api,cid]);
  useEffect(()=>{loadCams();},[loadCams]);
  const disc=async()=>{setErr('');try{const r=await api.get(`/cctv/discover?q=${encodeURIComponent(q)}`);setFound(r.data);}catch(e){setErr(e.message);}};
  const reg2=async()=>{if(!reg.ip)return;setErr('');try{await api.post('/cctv/register',{...reg,case_id:cid?+cid:null,port:+reg.port});setMsg('camera registered');setTimeout(()=>setMsg(''),2000);loadCams();}catch(e){setErr(e.message);}};
  return (
    <div style={S.section}>
      <h2 style={S.title}>CCTV / Sensor Infrastructure</h2>
      <p style={S.sub}>Map exposed camera coverage (metadata/exposure only — never device login) + custody for authorized feeds you hold.</p>
      <div style={S.row}>
        <select style={S.select} value={cid} onChange={e=>setCid(e.target.value)}><option value="">select case…</option>{cases.map(c=><option key={c.id} value={c.id}>{c.case_number}</option>)}</select>
        <input style={{...S.input,flex:1,minWidth:160}} placeholder="discovery query (product:camera …)" value={q} onChange={e=>setQ(e.target.value)}/>
        <button style={{...S.btn,background:'#8957e5'}} onClick={disc}>Discover</button>
      </div>
      <Err e={err}/>{msg&&<div style={{color:'#2ecc71',fontSize:12,marginTop:6}}>{msg}</div>}
      {found&&<div style={{marginTop:10}}>
        <div style={S.label}>mode: {found.mode} · {found.total??(found.results||[]).length} result(s){found.note?` — ${found.note}`:''}</div>
        {(found.results||[]).map((r,i)=><div key={i} style={S.card}><KV k="ip" v={`${r.ip}:${r.port}`}/><KV k="product" v={r.product}/><KV k="loc" v={`${r.city||''} ${r.country||''}`}/></div>)}
      </div>}
      <div style={{marginTop:16}}>
        <div style={S.label}>Register a known camera</div>
        <div style={S.row}>
          <input style={{...S.input,width:130}} placeholder="ip" value={reg.ip} onChange={e=>setReg({...reg,ip:e.target.value})}/>
          <input style={{...S.input,width:70}} placeholder="port" value={reg.port} onChange={e=>setReg({...reg,port:e.target.value})}/>
          <input style={{...S.input,width:110}} placeholder="label" value={reg.label} onChange={e=>setReg({...reg,label:e.target.value})}/>
          <input style={{...S.input,width:80}} placeholder="lat" value={reg.lat} onChange={e=>setReg({...reg,lat:e.target.value})}/>
          <input style={{...S.input,width:80}} placeholder="lon" value={reg.lon} onChange={e=>setReg({...reg,lon:e.target.value})}/>
          <button style={S.btn} onClick={reg2}>Register</button>
        </div>
      </div>
      <div style={{marginTop:16}}>
        <div style={S.label}>Registered cameras — {cams.length}</div>
        {cams.map(c=><div key={c.id} style={{...S.card}}><span style={{...S.mono,color:'#e6edf3'}}>{c.value}</span> <span style={S.tag}>{c.meta?.label||'—'}</span><span style={{color:'#8b949e',fontSize:12}}> {c.meta?.lat},{c.meta?.lon}</span></div>)}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- IoT
export function IotPanel({ api }) {
  const [cases,setCases]=useState([]); const [cid,setCid]=useState('');
  const [dev,setDev]=useState({name:'',type:'camera',ip:'',port:80});
  const [devices,setDevices]=useState([]); const [err,setErr]=useState(''); const [msg,setMsg]=useState('');
  const [scanRes,setScanRes]=useState(null);
  useEffect(()=>{api.get('/cases').then(r=>setCases(r.data)).catch(()=>{});},[api]);
  const load=useCallback(async()=>{try{const r=await api.get(`/iot/devices${cid?`?case_id=${cid}`:''}`);setDevices(r.data);}catch(e){setErr(e.message);}},[api,cid]);
  useEffect(()=>{load();},[load]);
  const reg=async()=>{if(!dev.ip)return;setErr('');try{await api.post('/iot/register',{...dev,case_id:cid?+cid:null,port:+dev.port});setMsg('device registered');setTimeout(()=>setMsg(''),2000);load();}catch(e){setErr(e.message);}};
  const scan=async(id)=>{setErr('');try{const r=await api.post(`/iot/scan/${id}`);setScanRes(r.data);}catch(e){setErr(e.message);}};
  const scanAll=async()=>{setErr('');try{const r=await api.post('/iot/scan_all',{case_id:cid?+cid:null});setMsg(`scanned ${r.data.scanned}, changed ${r.data.changed}, errors ${r.data.errors}`);setTimeout(()=>setMsg(''),4000);}catch(e){setErr(e.message);}};
  return (
    <div style={S.section}>
      <h2 style={S.title}>IoT Device Register + Exposure Monitor</h2>
      <p style={S.sub}>Permanent asset register. "Access back anytime" = re-scan public exposure state (banner/port) and diff changes — no device login. Lawful engagement via authority-gated gateway.</p>
      <div style={S.row}>
        <select style={S.select} value={cid} onChange={e=>setCid(e.target.value)}><option value="">select case…</option>{cases.map(c=><option key={c.id} value={c.id}>{c.case_number}</option>)}</select>
        <button style={{...S.btn,background:'#e67e22'}} onClick={scanAll}>Re-scan all</button>
      </div>
      <Err e={err}/>{msg&&<div style={{color:'#2ecc71',fontSize:12,marginTop:6}}>{msg}</div>}
      <div style={{marginTop:14}}>
        <div style={S.label}>Register device</div>
        <div style={S.row}>
          <input style={{...S.input,width:120}} placeholder="name" value={dev.name} onChange={e=>setDev({...dev,name:e.target.value})}/>
          <select style={S.select} value={dev.type} onChange={e=>setDev({...dev,type:e.target.value})}><option>camera</option><option>router</option><option>nvr</option><option>sensor</option><option>generic</option></select>
          <input style={{...S.input,width:140}} placeholder="ip" value={dev.ip} onChange={e=>setDev({...dev,ip:e.target.value})}/>
          <input style={{...S.input,width:70}} placeholder="port" value={dev.port} onChange={e=>setDev({...dev,port:e.target.value})}/>
          <button style={S.btn} onClick={reg}>Register</button>
        </div>
      </div>
      <div style={{marginTop:16}}>
        <div style={S.label}>Devices — {devices.length}</div>
        {devices.map(d=><div key={d.id} style={{...S.card}}>
          <div style={S.row}>
            <span style={{...S.mono,color:'#e6edf3'}}>{d.value}</span>
            <span style={S.tag}>{d.meta?.type}</span>
            <span style={{color:'#8b949e',fontSize:12}}>{d.meta?.name}</span>
            <button style={{...S.btn,background:'#30363d',padding:'3px 10px',fontSize:11}} onClick={()=>scan(d.id)}>Re-scan</button>
          </div>
          <div style={{color:'#484f58',fontSize:11,marginTop:4}}>seen {d.last_seen}</div>
        </div>)}
      </div>
      {scanRes&&(
        <div style={{marginTop:14}}>
          <div style={S.label}>Latest scan {scanRes.snapshot?.open?'— OPEN':'— closed'} {scanRes.changes?`· ${scanRes.changes.length} change(s)`:''}</div>
          <pre style={S.pre}>{JSON.stringify(scanRes.snapshot,null,2)}</pre>
          {scanRes.alert&&<div style={{...S.card,border:'1px solid #e67e22',color:'#e67e22',fontSize:13}}>{scanRes.alert.message}</div>}
        </div>)}
    </div>
  );
}

// ---------------------------------------------------------------- CORPORATE
export function CorporatePanel({ api }) {
  const [q,setQ]=useState(''); const [res,setRes]=useState(null);
  const [officers,setOfficers]=useState(null); const [err,setErr]=useState('');
  const search=async()=>{if(!q)return;setErr('');try{const r=await api.get(`/corporate/search?q=${encodeURIComponent(q)}`);setRes(r.data);}catch(e){setErr(e.message);}};
  const off=async(n,j)=>{setErr('');try{const r=await api.get(`/corporate/officers?number=${encodeURIComponent(n)}&jurisdiction=${encodeURIComponent(j||'')}`);setOfficers(r.data);}catch(e){setErr(e.message);}};
  return (
    <div style={S.section}>
      <h2 style={S.title}>Corporate Ownership Graph</h2>
      <p style={S.sub}>Search companies (Wikidata free + OpenCorporates with key), pull officers, link person→company edges into the case graph.</p>
      <div style={S.row}>
        <input style={{...S.input,flex:1}} placeholder="company name" value={q} onChange={e=>setQ(e.target.value)} onKeyDown={e=>e.key==='Enter'&&search()}/>
        <button style={S.btn} onClick={search}>Search</button>
      </div>
      <Err e={err}/>
      {res&&<div style={{marginTop:12}}>
        <div style={S.label}>{res.count} result(s) — sources: {res.sources?.join(', ')}{typeof res.opencorporates==='string'?` · OC: ${res.opencorporates}`:''}</div>
        {(res.results||[]).map((r,i)=><div key={i} style={S.card}>
          <div style={{color:'#e6edf3',fontWeight:600}}>{r.name}</div>
          <div style={{color:'#8b949e',fontSize:12}}>{r.description||r.jurisdiction} {r.source==='wikidata'?`· ${r.wikidata_id}`:''}</div>
          <div style={{marginTop:6}}>
            <button style={{...S.btn,background:'#30363d',padding:'3px 10px',fontSize:11}} onClick={()=>off(r.wikidata_id||r.number,r.jurisdiction)}>Officers</button>
            {r.url&&<a href={r.url} target="_blank" rel="noreferrer" style={{color:'#58a6ff',fontSize:11,marginLeft:8}}>open</a>}
          </div>
        </div>)}
      </div>}
      {officers&&<div style={{marginTop:12}}>
        <div style={S.label}>{officers.officers?.length||0} officer(s) — {officers.label||officers.qid}</div>
        {(officers.officers||[]).map((o,i)=><div key={i} style={{...S.card}}><span style={{color:'#e6edf3'}}>{o.name}</span> <span style={S.tag}>{o.role}</span></div>)}
        {officers.skipped&&<div style={{color:'#8b949e',fontSize:12}}>{officers.skipped}</div>}
      </div>}
    </div>
  );
}

// ---------------------------------------------------------------- CRYPTO
export function CryptoPanel({ api }) {
  const [addr,setAddr]=useState(''); const [ov,setOv]=useState(null);
  const [flow,setFlow]=useState(null); const [err,setErr]=useState('');
  const lookup=async()=>{if(!addr)return;setErr('');setFlow(null);try{const r=await api.post('/crypto/address',{address:addr});setOv(r.data);}catch(e){setErr(e.message);}};
  const trace=async()=>{if(!addr)return;setErr('');try{const r=await api.post('/crypto/trace',{address:addr});setFlow(r.data);}catch(e){setErr(e.message);}};
  return (
    <div style={S.section}>
      <h2 style={S.title}>Crypto Wallet Tracing</h2>
      <p style={S.sub}>Public blockchain analysis — balance, tx history, and 1-hop fund-flow graph (BTC via Blockstream, ETH via public RPC).</p>
      <div style={S.row}>
        <input style={{...S.input,flex:1}} placeholder="BTC (bc1…/1…/3…) or ETH (0x…)" value={addr} onChange={e=>setAddr(e.target.value.trim())} onKeyDown={e=>e.key==='Enter'&&lookup()}/>
        <button style={S.btn} onClick={lookup}>Overview</button>
        <button style={{...S.btn,background:'#e67e22'}} onClick={trace}>Trace flow</button>
      </div>
      <Err e={err}/>
      {ov&&!ov.error&&(
        <div style={{...S.card,marginTop:12}}>
          <div style={S.row}><span style={{...S.pill,background:ov.chain==='btc'?'#f7931a':'#627eea'}}>{ov.chain?.toUpperCase()}</span>
            <span style={{color:'#e6edf3',fontSize:13}}>balance: {ov.balance_btc??ov.balance_eth??'—'}</span></div>
          <div style={{marginTop:6,fontSize:12,color:'#8b949e'}}><KV k="tx count" v={ov.tx_count}/></div>
        </div>)}
      {flow&&!flow.error&&(
        <div style={{marginTop:14}}>
          <div style={S.label}>Fund flow — {flow.node_count} nodes / {flow.edge_count} edges</div>
          {flow.edges.map((e,i)=><div key={i} style={{...S.card}}>
            <span style={{...S.mono,color:e.relation==='sent_to'?'#2ecc71':'#e74c3c'}}>{e.relation}</span>
            <span style={{...S.mono,color:'#e6edf3',marginLeft:8}}>{(e.from===flow.seed?e.to:e.from)?.slice(0,26)}…</span>
            <span style={{color:'#8b949e',fontSize:12,marginLeft:8}}>{e.value_btc} BTC</span>
          </div>)}
        </div>)}
    </div>
  );
}

// ---------------------------------------------------------------- SCREENING
export function ScreenPanel({ api }) {
  const [name,setName]=useState(''); const [one,setOne]=useState(null);
  const [batch,setBatch]=useState(''); const [bres,setBres]=useState(null);
  const [lists,setLists]=useState(null); const [err,setErr]=useState('');
  useEffect(()=>{api.get('/screening/lists').then(r=>setLists(r.data)).catch(()=>{});},[api]);
  const scr=async()=>{if(!name)return;setErr('');try{const r=await api.post('/screening/name',{name});setOne(r.data);}catch(e){setErr(e.message);}};
  const scrB=async()=>{const names=batch.split('\n').map(x=>x.trim()).filter(Boolean);if(!names.length)return;setErr('');try{const r=await api.post('/screening/batch',{names});setBres(r.data);}catch(e){setErr(e.message);}};
  const badge=(h)=>h?{...S.pill,background:'#e74c3c'}:{...S.pill,background:'#2ecc71'};
  return (
    <div style={S.section}>
      <h2 style={S.title}>Sanctions / PEP / Watchlist Screening</h2>
      <p style={S.sub}>Screen names against OFAC SDN + UN consolidated lists (public, fuzzy match).</p>
      {lists&&<div style={{color:'#8b949e',fontSize:12,marginBottom:10}}>lists loaded — OFAC: {lists.OFAC_SDN} · UN: {lists.UN}</div>}
      <div style={S.row}>
        <input style={{...S.input,flex:1}} placeholder="name to screen" value={name} onChange={e=>setName(e.target.value)} onKeyDown={e=>e.key==='Enter'&&scr()}/>
        <button style={{...S.btn,background:'#e74c3c'}} onClick={scr}>Screen</button>
      </div>
      <Err e={err}/>
      {one&&(
        <div style={{marginTop:12}}>
          <div style={S.row}><span style={badge(one.hit)}>{one.hit?'LISTED — HIT':'no match'}</span>
            <span style={{color:'#8b949e',fontSize:12}}>{one.matches} fuzzy match(es)</span></div>
          {(one.results||[]).map((r,i)=><div key={i} style={{...S.card}}>
            <div style={S.row}><span style={{color:'#e6edf3',fontWeight:600}}>{r.name}</span>
              <span style={badge(r.score>=0.9)}>{Math.round(r.score*100)}%</span>
              <span style={S.tag}>{r.source}</span><span style={{color:'#8b949e',fontSize:12}}>{r.country||r.type}</span></div>
          </div>)}
        </div>)}
      <div style={{marginTop:16}}>
        <div style={S.label}>Batch screening (one name per line)</div>
        <textarea style={{...S.input,minHeight:80,resize:'vertical'}} value={batch} onChange={e=>setBatch(e.target.value)}/>
        <button style={{...S.btn,background:'#e67e22',marginTop:8}} onClick={scrB}>Screen batch</button>
        {bres&&<div style={{marginTop:10,color:bres.hits?'#e74c3c':'#2ecc71',fontSize:13}}>
          screened {bres.screened} · hits {bres.hits}</div>}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- INFRA PIVOT
export function InfraPanel({ api }) {
  const [target,setTarget]=useState(''); const [mode,setMode]=useState('ip');
  const [res,setRes]=useState(null); const [err,setErr]=useState('');
  const run=async()=>{if(!target)return;setErr('');try{const r=await api.post(`/infra/${mode}`,{[mode]:target});setRes(r.data);}catch(e){setErr(e.message);}};
  return (
    <div style={S.section}>
      <h2 style={S.title}>Infrastructure Attribution</h2>
      <p style={S.sub}>Pivot an IP or domain → PTR, ASN/operator, hosting flag, and co-hosted domains (shared-infrastructure discovery).</p>
      <div style={S.row}>
        <select style={S.select} value={mode} onChange={e=>setMode(e.target.value)}><option value="ip">IP</option><option value="domain">domain</option></select>
        <input style={{...S.input,flex:1}} placeholder={mode==='ip'?'8.8.8.8':'example.com'} value={target} onChange={e=>setTarget(e.target.value.trim())} onKeyDown={e=>e.key==='Enter'&&run()}/>
        <button style={S.btn} onClick={run}>Pivot</button>
      </div>
      <Err e={err}/>
      {res&&!res.error&&(
        <div style={{marginTop:12}}>
          <div style={S.card}>
            {res.asn?.asn&&<KV k="ASN" v={res.asn.asn}/>}
            {res.asn?.org&&<KV k="Org" v={res.asn.org}/>}
            {res.asn?.isp&&<KV k="ISP" v={res.asn.isp}/>}
            <KV k="Hosting" v={String(res.asn?.hosting)}/>
            <KV k="Proxy/VPN" v={String(res.asn?.proxy)}/>
            <KV k="Location" v={`${res.asn?.city||''} ${res.asn?.country||''}`}/>
            {res.ptr?.ptr&&<KV k="PTR" v={res.ptr.ptr}/>}
            {res.ip&&<KV k="IP" v={res.ip}/>}
            {res.domain&&<KV k="Domain" v={res.domain}/>}
          </div>
          {(res.co_hosted_domains?.length||res.shared_ip_domains?.length)>0&&(
            <div>
              <div style={S.label}>Co-hosted / shared-infrastructure domains</div>
              {(res.co_hosted_domains||res.shared_ip_domains||[]).map((d,i)=><div key={i} style={{...S.card,...S.mono,color:'#58a6ff'}}>{d}</div>)}
            </div>)}
        </div>)}
    </div>
  );
}
