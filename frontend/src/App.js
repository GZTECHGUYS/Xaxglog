import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, PieChart, Pie, Cell
} from 'recharts';
import './App.css';
import { ReconPanel, AttributionPanel, DarkWebPanel, SimSwapPanel, SS7Panel, CasesPanel } from './OperatorPanels';
import { GeoPanel, VehiclePanel, CctvPanel, IotPanel, CorporatePanel, CryptoPanel, ScreenPanel, InfraPanel } from './IntelPanels';
import { PlaybookPanel, GlobalCorpPanel, WorldRiskPanel, GeoExtraPanel, AiBriefPanel, TrackersPanel } from './DeepPanels';
import { PatternPanel } from './PatternPanel';
import { BonusPanel } from './BonusPanel';

const API = process.env.REACT_APP_API
  ? `${process.env.REACT_APP_API.replace(/\/$/, '')}/api`
  : (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
    ? `${window.location.protocol}//${window.location.hostname}:5000/api`
    : 'https://osint-app-8c1i.onrender.com/api';

// token persisted after login; attached to every request
const getToken = () => { try { return localStorage.getItem('xg_token'); } catch { return null; } };

const scoreColour = (score) => {
  if (score >= 75) return '#e74c3c';
  if (score >= 50) return '#e67e22';
  if (score >= 25) return '#f1c40f';
  return '#2ecc71';
};

const PIE_COLOURS = ['#3498db', '#e74c3c', '#2ecc71', '#9b59b6', '#f39c12'];

export default function App() {
  const [stats, setStats]               = useState(null);
  const [threats, setThreats]           = useState([]);
  const [search, setSearch]             = useState('');
  const [typeFilter, setTypeFilter]     = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [sortBy, setSortBy]             = useState('score');
  const [activeFilter] = useState('');
  const [loading, setLoading]           = useState(true);
  const [page, setPage]                 = useState(1);
  const perPage = 200;

  // Lookup feature state
  const [lookupQuery,   setLookupQuery]   = useState('');
  const [lookupResult,  setLookupResult]  = useState(null);
  const [lookupLoading, setLookupLoading] = useState(false);

  // AI Threat Summary state
  const [aiSummary,        setAiSummary]        = useState(null);
  const [aiSummaryLoading, setAiSummaryLoading] = useState(false);
  const [aiSummaryError,   setAiSummaryError]   = useState('');
  const [aiProvider,       setAiProvider]       = useState('');

  // Have I Been Pwned state
  const [breachEmail,   setBreachEmail]   = useState('');
  const [breachResult,  setBreachResult]  = useState(null);
  const [breachLoading, setBreachLoading] = useState(false);
  const [breachError,   setBreachError]   = useState('');

  // Snort/YARA rule generation state
  const [rulesModal,    setRulesModal]    = useState(null);
  const [rulesMode,     setRulesMode]     = useState('template');
  const [rulesContent,  setRulesContent]  = useState('');
  const [rulesTemplate, setRulesTemplate] = useState(null);
  const [rulesLoading,  setRulesLoading]  = useState(false);

  // Alerts state
  const [alerts, setAlerts] = useState([]);
  const [showAlerts, setShowAlerts] = useState(true);

  // Bulk protect state
  const [bulkPeriod, setBulkPeriod] = useState('1day');
  const [bulkMinScore, setBulkMinScore] = useState(0);
  const [bulkResult, setBulkResult] = useState(null);
  const [bulkLoading, setBulkLoading] = useState(false);
  const [bulkMode, setBulkMode] = useState('template');

  // API Key management state
  const [showKeyModal, setShowKeyModal] = useState(false);
  const [savedServices, setSavedServices] = useState([]);
  const [keyInputs, setKeyInputs] = useState({});
  const [keyStatus, setKeyStatus] = useState({});
  const [validatingKey, setValidatingKey] = useState('');
  const [savingKey, setSavingKey] = useState('');

  // Responsive: switch to a single-column layout on small screens.
  // Desktop styles are completely unchanged when isMobile is false.
  const [isMobile, setIsMobile] = useState(
    typeof window !== 'undefined' && window.innerWidth <= 768
  );
  useEffect(() => {
    const onResize = () => setIsMobile(window.innerWidth <= 768);
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);
  const s = makeStyles(isMobile);

  // ---- Auth + tab navigation
  const [user, setUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem('xg_user')); } catch { return null; }
  });
  const [tab, setTab] = useState('threat');
  const [login, setLogin] = useState({ username: '', password: '' });
  const [loginErr, setLoginErr] = useState('');
  const [loginBusy, setLoginBusy] = useState(false);

  const doLogin = async (e) => {
    e && e.preventDefault();
    if (!login.username || !login.password) return;
    setLoginBusy(true); setLoginErr('');
    try {
      const r = await axios.post(`${API}/auth/login`, login);
      localStorage.setItem('xg_token', r.data.token);
      localStorage.setItem('xg_user', JSON.stringify(r.data.user));
      setUser(r.data.user);
      setLogin({ username: '', password: '' });
    } catch (err) {
      setLoginErr(err.response?.data?.error || 'Login failed');
    }
    setLoginBusy(false);
  };
  const doLogout = () => {
    localStorage.removeItem('xg_token'); localStorage.removeItem('xg_user');
    setUser(null); setTab('threat');
  };

  const api = axios.create({ baseURL: API, withCredentials: true });
  api.interceptors.request.use(cfg => {
    const t = getToken();
    if (t) cfg.headers.Authorization = `Bearer ${t}`;
    return cfg;
  });

  useEffect(() => {
    api.get('/keys').then(res => setSavedServices(res.data.services || [])).catch(() => {});
  }, []);

  const saveKey = async (service) => {
    const key = keyInputs[service];
    if (!key) return;
    setSavingKey(service);
    try {
      await api.post('/keys', { service, key });
      setSavedServices(prev => [...new Set([...prev, service])]);
      setKeyInputs(prev => ({ ...prev, [service]: '' }));
      setKeyStatus(prev => ({ ...prev, [service]: 'saved' }));
    } catch {
      setKeyStatus(prev => ({ ...prev, [service]: 'error' }));
    }
    setSavingKey('');
  };

  const removeKey = async (service) => {
    try {
      await api.delete(`/keys/${service}`);
      setSavedServices(prev => prev.filter(s => s !== service));
      setKeyStatus(prev => { const n = {...prev}; delete n[service]; return n; });
    } catch {}
  };

  const validateKey = async (service) => {
    const key = keyInputs[service];
    if (!key) return;
    setValidatingKey(service);
    try {
      const res = await api.post('/validate-key', { service, key });
      setKeyStatus(prev => ({...prev, [service]: res.data.valid ? 'valid' : 'invalid'}));
    } catch {
      setKeyStatus(prev => ({...prev, [service]: 'invalid'}));
    }
    setValidatingKey('');
  };

  const activeKeyCount = savedServices.length;

  useEffect(() => {
    Promise.all([
      api.get('/stats'),
      api.get('/threats'),
      api.get('/alerts?min_score=30')
    ]).then(([statsRes, threatsRes, alertsRes]) => {
      setStats(statsRes.data);
      setThreats(threatsRes.data.threats);
      setAlerts(alertsRes.data.alerts || []);
      setLoading(false);
    }).catch(err => {
      console.error('Failed to fetch data:', err);
      setLoading(false);
    });
  }, []);

  const handleLookup = async () => {
    if (!lookupQuery.trim()) return;
    setLookupLoading(true);
    setLookupResult(null);
    try {
      const res = await api.get(`/lookup?value=${encodeURIComponent(lookupQuery)}`);
      setLookupResult(res.data);
    } catch (err) {
      console.error('Lookup failed:', err);
    }
    setLookupLoading(false);
  };

  const handleAiSummary = async () => {
    setAiSummaryLoading(true);
    setAiSummaryError('');
    setAiSummary(null);
    try {
      const res = await api.post('/ai-summary', {});
      setAiSummary(res.data.summary);
      setAiProvider(res.data.provider || '');
    } catch (err) {
      setAiSummaryError(err.response?.data?.error || 'Failed to generate AI summary');
    }
    setAiSummaryLoading(false);
  };

  const handleBreachLookup = async () => {
    if (!breachEmail.trim()) return;
    setBreachLoading(true);
    setBreachError('');
    setBreachResult(null);
    try {
      const res = await api.get(`/breach-lookup?email=${encodeURIComponent(breachEmail)}`);
      setBreachResult(res.data);
    } catch (err) {
      setBreachError(err.response?.data?.error || 'Breach lookup failed');
    }
    setBreachLoading(false);
  };

  const handleProtect = async (threat) => {
    setRulesModal(threat);
    setRulesMode('template');
    setRulesContent('');
    setRulesTemplate(null);
    setRulesLoading(true);
    try {
      const res = await api.post('/template-rules', {
        indicator_value: threat.indicator_value,
        indicator_type:  threat.indicator_type,
        threat_score:    threat.threat_score,
        tags:            threat.tags || [],
        source:          threat.source,
        description:     threat.description || ''
      });
      setRulesTemplate(res.data);
    } catch (err) {
      setRulesTemplate({ error: err.response?.data?.error || err.message });
    }
    setRulesLoading(false);
  };

  const handleAiRules = async () => {
    setRulesMode('ai');
    setRulesContent('');
    setRulesLoading(true);
    try {
      const res = await api.post('/generate-rules', {
        indicator_value: rulesModal.indicator_value,
        indicator_type:  rulesModal.indicator_type,
        threat_score:    rulesModal.threat_score,
        tags:            rulesModal.tags || [],
        source:          rulesModal.source,
        description:     rulesModal.description || ''
      });
      setRulesContent(res.data.rules);
    } catch (err) {
      setRulesContent('Error generating AI rules: ' +
        (err.response?.data?.error || err.message));
    }
    setRulesLoading(false);
  };

  const handleBulkProtect = async () => {
    setBulkLoading(true);
    setBulkResult(null);
    try {
      const res = await api.post('/bulk-protect', {
        period: bulkPeriod,
        use_ai: bulkMode === 'ai',
        min_score: bulkMinScore
      });
      setBulkResult(res.data);
    } catch (err) {
      setBulkResult({ error: err.response?.data?.error || err.message });
    }
    setBulkLoading(false);
  };

  const filtered = threats.filter(t => {
    const matchSearch = t.indicator_value.toLowerCase().includes(search.toLowerCase());
    const matchType   = typeFilter ? t.indicator_type === typeFilter : true;
    const matchSource = sourceFilter ? t.source === sourceFilter : true;
    const matchActive = activeFilter !== '' ? t.is_active === parseInt(activeFilter) : true;
    return matchSearch && matchType && matchSource && matchActive;
  }).sort((a, b) => {
    if (sortBy === 'score') return b.threat_score - a.threat_score;
    if (sortBy === 'newest') return (b.first_seen || '').localeCompare(a.first_seen || '');
    if (sortBy === 'oldest') return (a.first_seen || '').localeCompare(b.first_seen || '');
    return 0;
  });

  const totalPages = Math.ceil(filtered.length / perPage);
  const paged = filtered.slice((page - 1) * perPage, page * perPage);

  if (loading && user) return (
    <div style={s.loading}>Loading threat data...</div>
  );

  if (!user) {
    return (
      <div style={{minHeight:'100vh', display:'flex', alignItems:'center', justifyContent:'center',
        background:'#0d1117', padding:20}}>
        <form onSubmit={doLogin} style={{background:'#161b22', border:'1px solid #30363d',
          borderRadius:12, padding:'32px 32px', width:360}}>
          <div style={{textAlign:'center', marginBottom:20}}>
            <div style={{fontSize:24, fontWeight:800, color:'#e6edf3', letterSpacing:'0.02em'}}>Xaxglog</div>
            <div style={{fontSize:12, color:'#8b949e', marginTop:4}}>State-grade OSINT Intelligence Platform</div>
          </div>
          <label style={{fontSize:11, color:'#8b949e', display:'block', marginBottom:4}}>Username</label>
          <input style={{...s.input, marginBottom:12}} value={login.username}
            onChange={e => setLogin({...login, username:e.target.value})} autoFocus />
          <label style={{fontSize:11, color:'#8b949e', display:'block', marginBottom:4}}>Password</label>
          <input type="password" style={{...s.input, marginBottom:16}} value={login.password}
            onChange={e => setLogin({...login, password:e.target.value})} />
          {loginErr && (
            <div style={{background:'#2a1a1a', border:'1px solid #e74c3c', borderRadius:6,
              padding:'8px 12px', color:'#e74c3c', fontSize:12, marginBottom:12}}>{loginErr}</div>
          )}
          <button type="submit" style={{...s.btn, width:'100%', background:'#238636'}}
            disabled={loginBusy}>{loginBusy ? 'Signing in…' : 'Sign in'}</button>
          <div style={{fontSize:11, color:'#484f58', marginTop:16, textAlign:'center', lineHeight:1.5}}>
            First run: admin / xaxglog-admin — change via XAXGLOG_ADMIN_PASSWORD
          </div>
        </form>
      </div>
    );
  }

  const criticalCount = threats.filter(t => t.threat_score >= 75).length;
  const scoreData = stats?.by_score?.map(x => ({ score: `${x.score}`, count: x.count })) || [];
  const sourceData = Object.entries(stats?.by_source || {}).map(([name, value]) => ({ name, value }));

  return (
    <div style={s.page}>

      {/*  HEADER  */}
      <header style={s.header}>
        <div style={{position:'relative', textAlign:'center'}}>
          <h1 style={s.headerTitle}>OSINT Threat Dashboard</h1>
          <p style={s.headerSub}>
            Collect, analyse and respond to cyber threats from {Object.keys(stats?.by_source || {}).length + 9} intelligence sources
          </p>
          <button
            style={{...s.keyBtn, ...s.keyBtnPos}}
            onClick={() => setShowKeyModal(true)}
          >
            API Keys
            {activeKeyCount > 0 && (
              <span style={s.keyBadge}>{activeKeyCount}</span>
            )}
          </button>
        </div>

        {/* Compact stats bar */}
        <div style={s.statsBar}>
          <div style={s.statItem}>
            <span style={{...s.statNum, color:'#e74c3c'}}>{criticalCount}</span>
            <span style={s.statLabel}>Critical (75+)</span>
          </div>
          <div style={s.statDivider}/>
          <div style={s.statItem}>
            <span style={s.statNum}>{stats?.active ?? 0}</span>
            <span style={s.statLabel}>Active threats</span>
          </div>
          <div style={s.statDivider}/>
          <div style={s.statItem}>
            <span style={s.statNum}>{stats?.total ?? 0}</span>
            <span style={s.statLabel}>Total collected</span>
          </div>
          <div style={s.statDivider}/>
          {Object.entries(stats?.by_source || {}).map(([src, count]) => (
            <div key={src} style={s.statItem}>
              <span style={{...s.statNum, fontSize:16}}>{count}</span>
              <span style={s.statLabel}>{src}</span>
            </div>
          ))}
        </div>
      </header>

      {/* TAB NAVIGATION */}
      <div style={{display:'flex', gap:6, flexWrap:'wrap', padding:'0 20px 16px',
        borderBottom:'1px solid #30363d', marginBottom:16}}>
        {[
          ['threat','Threat Intel'],['cases','Cases & Graph'],['recon','Deep Recon'],
          ['attribution','Attribution'],['darkweb','Dark Web'],['simswap','SIM-Swap'],['ss7','SS7 Lookup'],
          ['geo','GEOINT Map'],['vehicle','Vehicles'],['cctv','CCTV'],['iot','IoT'],
          ['corporate','Corporate'],['crypto','Crypto'],['screening','Screening'],['infra','Infra Pivot'],
          ['playbooks','Playbooks'],['worldcorp','Global Corp'],['risk','World Risk'],
          ['geoextra','Geo Extra'],['aibrief','AI Brief'],['trackers','Trackers'],
          ['pattern','Pattern Tracker'],['offsec','Offsec Intel'],
        ].map(([k,label]) => (
          <button key={k} onClick={()=>setTab(k)} className={tab===k?'tabBtn active':'tabBtn'} style={{
            background: tab===k ? '#1f6feb' : '#21262d',
            color: tab===k ? '#fff' : '#8b949e',
            border:'none', borderRadius:6, padding:'8px 14px', fontSize:13, fontWeight:600, cursor:'pointer'
          }}>{label}</button>
        ))}
        <div style={{marginLeft:'auto', display:'flex', alignItems:'center', gap:10}}>
          <span style={{fontSize:12, color:'#8b949e'}}>{user.username} · {user.role}</span>
          <button onClick={doLogout} style={{background:'#21262d', color:'#e74c3c', border:'1px solid #30363d',
            borderRadius:6, padding:'7px 12px', fontSize:12, cursor:'pointer'}}>Sign out</button>
        </div>
      </div>

      <div style={s.content}>

        {/* OPERATOR PANELS (non-threat tabs) */}
        {tab==='cases'      && <CasesPanel api={api} />}
        {tab==='recon'      && <ReconPanel api={api} />}
        {tab==='attribution'&& <AttributionPanel api={api} />}
        {tab==='darkweb'    && <DarkWebPanel api={api} />}
        {tab==='simswap'    && <SimSwapPanel api={api} />}
        {tab==='ss7'        && <SS7Panel api={api} />}
        {tab==='geo'        && <GeoPanel api={api} />}
        {tab==='vehicle'    && <VehiclePanel api={api} />}
        {tab==='cctv'       && <CctvPanel api={api} />}
        {tab==='iot'        && <IotPanel api={api} />}
        {tab==='corporate'  && <CorporatePanel api={api} />}
        {tab==='crypto'     && <CryptoPanel api={api} />}
        {tab==='screening'  && <ScreenPanel api={api} />}
        {tab==='infra'      && <InfraPanel api={api} />}
        {tab==='playbooks'  && <PlaybookPanel api={api} />}
        {tab==='worldcorp'  && <GlobalCorpPanel api={api} />}
        {tab==='risk'       && <WorldRiskPanel api={api} />}
        {tab==='geoextra'   && <GeoExtraPanel api={api} />}
        {tab==='aibrief'    && <AiBriefPanel api={api} />}
        {tab==='trackers'   && <TrackersPanel api={api} />}
        {tab==='pattern'    && <PatternPanel api={api} />}
        {tab==='offsec'     && <BonusPanel api={api} />}

        {tab==='threat' && (<>
        {/*  ALERTS BANNER  */}
        {showAlerts && alerts.length > 0 && (
          <div style={{background:'#2a1a1a', border:'1px solid #e74c3c', borderRadius:8, padding:'14px 18px', marginBottom:16, position:'relative'}}>
            <button onClick={() => setShowAlerts(false)} style={{position:'absolute', top:8, right:12, background:'none', border:'none', color:'#8b949e', fontSize:16, cursor:'pointer'}}>x</button>
            <div style={{display:'flex', alignItems:'center', gap:10, marginBottom:8}}>
              <span style={{background:'#e74c3c', color:'#fff', padding:'2px 10px', borderRadius:12, fontSize:11, fontWeight:600}}>NEW THREATS</span>
              <span style={{color:'#e6edf3', fontSize:14, fontWeight:600}}>{alerts.length} high-score indicator{alerts.length !== 1 ? 's' : ''} detected in the last 24 hours</span>
            </div>
            <div style={{display:'flex', gap:6, flexWrap:'wrap'}}>
              {alerts.slice(0, 8).map((a, i) => (
                <span key={i} style={{background:'#161b22', border:'1px solid #30363d', borderRadius:6, padding:'4px 10px', fontSize:12, display:'inline-flex', alignItems:'center', gap:6}}>
                  <span style={{fontFamily:'monospace', color:'#58a6ff', maxWidth:200, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap'}}>{a.indicator_value}</span>
                  <span style={{...s.pill, background: scoreColour(a.threat_score), fontSize:10, padding:'1px 6px'}}>{a.threat_score}</span>
                </span>
              ))}
              {alerts.length > 8 && <span style={{color:'#8b949e', fontSize:12, alignSelf:'center'}}>+{alerts.length - 8} more</span>}
            </div>
          </div>
        )}

        {/*  TOOL GRID: 3 interactive tools  */}
        <div style={s.toolGrid}>

          {/* Tool 1: Indicator Lookup */}
          <div style={{...s.toolCard, borderTopColor:'#1f6feb'}}>
            <div style={s.toolHeader}>
              <span style={{...s.toolIcon, background:'#1f6feb'}}>?</span>
              <div>
                <div style={s.toolName}>Indicator Lookup</div>
                <div style={s.toolDesc}>
                  Search any IP, domain, URL or file hash across 7 live sources
                </div>
              </div>
            </div>
            <div style={s.toolSources}>
              {['AbuseIPDB','OTX','crt.sh','WHOIS','Shodan','SecurityTrails','IntelligenceX'].map(n => (
                <span key={n} style={s.sourcePill}>{n}</span>
              ))}
            </div>
            <div style={{display:'flex', gap:8}}>
              <input
                style={{...s.input, flex:1}}
                placeholder="e.g. 8.8.8.8 or example.com"
                value={lookupQuery}
                onChange={e => setLookupQuery(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleLookup()}
              />
              <button style={{...s.btn, background:'#1f6feb'}} onClick={handleLookup}
                disabled={lookupLoading}>
                {lookupLoading ? 'Searching...' : 'Search'}
              </button>
            </div>
          </div>

          {/* Tool 2: Email Breach Check */}
          <div style={{...s.toolCard, borderTopColor:'#e74c3c'}}>
            <div style={s.toolHeader}>
              <span style={{...s.toolIcon, background:'#e74c3c'}}>@</span>
              <div>
                <div style={s.toolName}>Email Breach Check</div>
                <div style={s.toolDesc}>
                  Check if an email has been exposed in breaches, paste dumps, or flagged as suspicious
                </div>
              </div>
            </div>
            <div style={s.toolSources}>
              <span style={s.sourcePill}>Have I Been Pwned</span>
              <span style={s.sourcePill}>XposedOrNot</span>
              <span style={s.sourcePill}>EmailRep</span>
            </div>
            <div style={{display:'flex', gap:8}}>
              <input
                style={{...s.input, flex:1}}
                placeholder="someone@example.com"
                value={breachEmail}
                onChange={e => setBreachEmail(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleBreachLookup()}
              />
              <button style={{...s.btn, background:'#e74c3c'}} onClick={handleBreachLookup}
                disabled={breachLoading}>
                {breachLoading ? 'Checking...' : 'Check'}
              </button>
            </div>
          </div>

          {/* Tool 3: AI Threat Briefing */}
          <div style={{...s.toolCard, borderTopColor:'#8957e5'}}>
            <div style={s.toolHeader}>
              <span style={{...s.toolIcon, background:'#8957e5'}}>AI</span>
              <div>
                <div style={s.toolName}>AI Threat Briefing</div>
                <div style={s.toolDesc}>
                  AI reads all your threat data and writes a plain-English security report
                </div>
              </div>
            </div>
            <div style={s.toolSources}>
              <span style={s.sourcePill}>Gemini AI</span>
              <span style={s.sourcePill}>Groq (fallback)</span>
            </div>
            <button
              style={{...s.btn, background: aiSummaryLoading ? '#333' : '#8957e5', width:'100%'}}
              onClick={handleAiSummary}
              disabled={aiSummaryLoading}
            >
              {aiSummaryLoading ? 'Analysing threats...' : 'Generate Briefing'}
            </button>
          </div>
        </div>

        {/*  RESULTS AREA: shows results from whichever tool was used  */}

        {/* Lookup results */}
        {lookupResult && (
          <div style={s.section}>
            <div style={s.sectionHeader}>
              <h2 style={s.sectionTitle}>
                Results for "{lookupResult.query}"
                <span style={{...s.typeBadge, marginLeft:10}}>
                  {lookupResult.indicator_type}
                </span>
              </h2>
            </div>

            {lookupResult.live && Object.keys(lookupResult.live).length > 0 && (
              <div style={s.liveGrid}>
                {/* AbuseIPDB */}
                {lookupResult.live.abuseipdb && !lookupResult.live.abuseipdb.error && (
                  <div style={s.liveCard}>
                    <div style={s.lcHeader}>
                      <span style={s.lcTitle}>AbuseIPDB</span>
                      <span style={{...s.pill, background: scoreColour(lookupResult.live.abuseipdb.confidence_score)}}>
                        {lookupResult.live.abuseipdb.confidence_score}% confidence
                      </span>
                    </div>
                    <div style={s.lcGrid}>
                      <div><span style={s.lcLabel}>Reports: </span>{lookupResult.live.abuseipdb.total_reports}</div>
                      <div><span style={s.lcLabel}>Country: </span>{lookupResult.live.abuseipdb.country}</div>
                      <div><span style={s.lcLabel}>ISP: </span>{lookupResult.live.abuseipdb.isp}</div>
                      <div><span style={s.lcLabel}>Usage: </span>{lookupResult.live.abuseipdb.usage_type}</div>
                      <div><span style={s.lcLabel}>Last reported: </span>
                        {lookupResult.live.abuseipdb.last_reported
                          ? new Date(lookupResult.live.abuseipdb.last_reported).toLocaleDateString()
                          : 'Never'}</div>
                      <div><span style={s.lcLabel}>Whitelisted: </span>
                        {lookupResult.live.abuseipdb.is_whitelisted ? 'Yes' : 'No'}</div>
                    </div>
                  </div>
                )}

                {/* Shodan */}
                {lookupResult.live.shodan && !lookupResult.live.shodan.error && (
                  <div style={s.liveCard}>
                    <div style={s.lcHeader}>
                      <span style={s.lcTitle}>Shodan</span>
                      <span style={{...s.pill,
                        background: lookupResult.live.shodan.ports.length > 5 ? '#e74c3c'
                          : lookupResult.live.shodan.ports.length > 0 ? '#e67e22' : '#2ecc71'
                      }}>
                        {lookupResult.live.shodan.ports.length} port{lookupResult.live.shodan.ports.length !== 1 ? 's' : ''}
                      </span>
                    </div>
                    <div style={s.lcGrid}>
                      <div><span style={s.lcLabel}>Org: </span>{lookupResult.live.shodan.org}</div>
                      <div><span style={s.lcLabel}>OS: </span>{lookupResult.live.shodan.os}</div>
                      <div><span style={s.lcLabel}>Location: </span>{lookupResult.live.shodan.city}, {lookupResult.live.shodan.country_name}</div>
                      <div><span style={s.lcLabel}>Ports: </span>{lookupResult.live.shodan.ports.slice(0,10).join(', ')}</div>
                    </div>
                    {lookupResult.live.shodan.vulns && lookupResult.live.shodan.vulns.length > 0 && (
                      <div style={{marginTop:6}}>
                        <span style={{color:'#e74c3c', fontSize:11, fontWeight:600}}>Vulns: </span>
                        {lookupResult.live.shodan.vulns.slice(0,6).map((v, i) => (
                          <span key={i} style={{...s.tag, background:'#3a1a1a', color:'#e74c3c', fontFamily:'monospace'}}>{v}</span>
                        ))}
                      </div>
                    )}
                    {lookupResult.live.shodan.services && lookupResult.live.shodan.services.length > 0 && (
                      <div style={{marginTop:6}}>
                        {lookupResult.live.shodan.services.map((sv, i) => (
                          <span key={i} style={{...s.tag, fontFamily:'monospace'}}>:{sv.port} {sv.product} {sv.version}</span>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* OTX */}
                {lookupResult.live.otx && !lookupResult.live.otx.error && (
                  <div style={s.liveCard}>
                    <div style={s.lcHeader}>
                      <span style={s.lcTitle}>AlienVault OTX</span>
                      <span style={{...s.pill, background: lookupResult.live.otx.pulse_count > 0 ? '#e74c3c' : '#2ecc71'}}>
                        {lookupResult.live.otx.pulse_count} report{lookupResult.live.otx.pulse_count !== 1 ? 's' : ''}
                      </span>
                    </div>
                    {lookupResult.live.otx.pulses && lookupResult.live.otx.pulses.length > 0 ? (
                      <div>
                        {lookupResult.live.otx.pulses.map((p, i) => (
                          <div key={i} style={{background:'#161b22', borderRadius:4, padding:'6px 10px', marginBottom:4}}>
                            <div style={{color:'#e6edf3', fontSize:12}}>{p.name}</div>
                            <div>{p.tags.slice(0,6).map(tag => (
                              <span key={tag} style={s.tag}>{tag}</span>
                            ))}</div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div style={{color:'#8b949e', fontSize:12}}>No threat campaigns found.</div>
                    )}
                  </div>
                )}

                {/* crt.sh */}
                {lookupResult.live.crtsh && (
                  lookupResult.live.crtsh.error ? (
                    <div style={s.liveCard}>
                      <div style={s.lcHeader}>
                        <span style={s.lcTitle}>crt.sh - Certificates</span>
                        <span style={{...s.pill, background:'#e74c3c'}}>Unavailable</span>
                      </div>
                      <div style={{fontSize:12, color:'#8b949e', marginTop:4}}>
                        {lookupResult.live.crtsh.error} - crt.sh frequently has upstream outages; try again in a minute.
                      </div>
                    </div>
                  ) : (
                    <div style={s.liveCard}>
                      <div style={s.lcHeader}>
                        <span style={s.lcTitle}>crt.sh - Certificates</span>
                        <span style={{...s.pill, background: lookupResult.live.crtsh.subdomain_count > 0 ? '#e67e22' : '#2ecc71'}}>
                          {lookupResult.live.crtsh.subdomain_count} subdomain{lookupResult.live.crtsh.subdomain_count !== 1 ? 's' : ''}
                        </span>
                      </div>
                      <div style={s.lcGrid}>
                        <div><span style={s.lcLabel}>Total certs: </span>{lookupResult.live.crtsh.total_certs}</div>
                        <div><span style={s.lcLabel}>Subdomains: </span>{lookupResult.live.crtsh.subdomain_count}</div>
                      </div>
                      {lookupResult.live.crtsh.subdomains && lookupResult.live.crtsh.subdomains.length > 0 && (
                        <div style={{marginTop:8, maxHeight:100, overflowY:'auto'}}>
                          {lookupResult.live.crtsh.subdomains.map((sub, i) => (
                            <span key={i} style={{...s.tag, fontFamily:'monospace', display:'inline-block', marginBottom:3}}>{sub}</span>
                          ))}
                        </div>
                      )}
                      {lookupResult.live.crtsh.issuers && lookupResult.live.crtsh.issuers.length > 0 && (
                        <div style={{marginTop:6}}>
                          <span style={s.lcLabel}>Issuers: </span>
                          {lookupResult.live.crtsh.issuers.map((iss, i) => (
                            <span key={i} style={s.tag}>{iss}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  )
                )}

                {/* WHOIS */}
                {lookupResult.live.whois && (
                  lookupResult.live.whois.error ? (
                    <div style={s.liveCard}>
                      <div style={s.lcHeader}>
                        <span style={s.lcTitle}>WHOIS</span>
                        <span style={{...s.pill, background:'#e74c3c'}}>Unavailable</span>
                      </div>
                      <div style={{fontSize:12, color:'#8b949e', marginTop:4}}>
                        {lookupResult.live.whois.error}
                      </div>
                    </div>
                  ) : (
                    <div style={s.liveCard}>
                      <div style={s.lcHeader}>
                        <span style={s.lcTitle}>WHOIS</span>
                        <span style={{...s.pill, background:'#3498db'}}>{lookupResult.live.whois.registrar}</span>
                      </div>
                      <div style={s.lcGrid}>
                        <div><span style={s.lcLabel}>Registrant: </span>{lookupResult.live.whois.registrant}</div>
                        <div><span style={s.lcLabel}>Created: </span>{lookupResult.live.whois.creation_date}</div>
                        <div><span style={s.lcLabel}>Expires: </span>{lookupResult.live.whois.expiration_date}</div>
                        <div><span style={s.lcLabel}>Nameservers: </span>
                          {(lookupResult.live.whois.name_servers || []).join(', ')}</div>
                      </div>
                    </div>
                  )
                )}

                {/* SecurityTrails */}
                {lookupResult.live.securitytrails && !lookupResult.live.securitytrails.error && (
                  <div style={s.liveCard}>
                    <div style={s.lcHeader}>
                      <span style={s.lcTitle}>SecurityTrails</span>
                      <span style={{...s.pill, background:'#9b59b6'}}>
                        {lookupResult.live.securitytrails.subdomain_count} subdomain{lookupResult.live.securitytrails.subdomain_count !== 1 ? 's' : ''}
                      </span>
                    </div>
                    <div style={s.lcGrid}>
                      <div><span style={s.lcLabel}>A Records: </span>{(lookupResult.live.securitytrails.a_records || []).join(', ') || 'None'}</div>
                      <div><span style={s.lcLabel}>MX Records: </span>{(lookupResult.live.securitytrails.mx_records || []).join(', ') || 'None'}</div>
                      <div><span style={s.lcLabel}>NS Records: </span>{(lookupResult.live.securitytrails.ns_records || []).join(', ') || 'None'}</div>
                      <div><span style={s.lcLabel}>Alexa Rank: </span>{lookupResult.live.securitytrails.alexa_rank}</div>
                    </div>
                    {lookupResult.live.securitytrails.subdomains && lookupResult.live.securitytrails.subdomains.length > 0 && (
                      <div style={{marginTop:6, maxHeight:80, overflowY:'auto'}}>
                        {lookupResult.live.securitytrails.subdomains.map((sub, i) => (
                          <span key={i} style={{...s.tag, fontFamily:'monospace'}}>{sub}</span>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* IntelligenceX */}
                {lookupResult.live.intelx && !lookupResult.live.intelx.error && (
                  <div style={s.liveCard}>
                    <div style={s.lcHeader}>
                      <span style={s.lcTitle}>IntelligenceX</span>
                      <span style={{...s.pill, background: lookupResult.live.intelx.total_results > 0 ? '#e74c3c' : '#2ecc71'}}>
                        {lookupResult.live.intelx.total_results} result{lookupResult.live.intelx.total_results !== 1 ? 's' : ''}
                      </span>
                    </div>
                    {lookupResult.live.intelx.source_types && Object.keys(lookupResult.live.intelx.source_types).length > 0 && (
                      <div style={{marginBottom:6}}>
                        {Object.entries(lookupResult.live.intelx.source_types).map(([bucket, count], i) => (
                          <span key={i} style={{...s.tag, background:'#1a1a2e', color:'#a78bfa'}}>{bucket}: {count}</span>
                        ))}
                      </div>
                    )}
                    {lookupResult.live.intelx.previews && lookupResult.live.intelx.previews.length > 0 && (
                      <div>
                        {lookupResult.live.intelx.previews.map((p, i) => (
                          <div key={i} style={{background:'#161b22', borderRadius:4, padding:'6px 10px', marginBottom:4}}>
                            <div style={{color:'#e6edf3', fontSize:12}}>{p.name}</div>
                            <div style={{color:'#8b949e', fontSize:11}}>{p.bucket} {p.date ? `- ${p.date.split('T')[0]}` : ''}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Local DB matches */}
            {lookupResult.found && (
              <div style={{marginTop:12}}>
                <div style={{background:'#1a2e1a', border:'1px solid #2ecc71', borderRadius:8, padding:'10px 14px', color:'#2ecc71', fontSize:13, marginBottom:10}}>
                  {lookupResult.count} match{lookupResult.count !== 1 ? 'es' : ''} in local database
                </div>
                {lookupResult.results.slice(0,5).map(r => (
                  <div key={r.id} style={s.resultRow}>
                    <span style={{fontFamily:'monospace', fontSize:12, color:'#58a6ff', wordBreak:'break-all'}}>{r.indicator_value}</span>
                    <span style={s.typeBadge}>{r.indicator_type}</span>
                    <span style={{color:'#8b949e', fontSize:12}}>{r.source}</span>
                    <span style={{...s.pill, background: scoreColour(r.threat_score)}}>{r.threat_score}</span>
                    {(r.tags || []).slice(0,3).map(tag => <span key={tag} style={s.tag}>{tag}</span>)}
                  </div>
                ))}
              </div>
            )}
            {lookupResult && !lookupResult.found && (
              <div style={{background:'#1a1a2e', border:'1px solid #30363d', borderRadius:8, padding:'10px 14px', color:'#8b949e', fontSize:13, marginTop:12}}>
                Not in local database - see live results above.
              </div>
            )}

            {/* Protect button for lookup results */}
            <div style={{marginTop:14}}>
              {lookupResult.resolved_ip && (
                <div style={{background:'#1a2e1a', border:'1px solid #2ecc71', borderRadius:8, padding:'10px 14px', marginBottom:8, fontSize:13, color:'#2ecc71'}}>
                  Resolved IP: <span style={{fontFamily:'monospace', fontWeight:600}}>{lookupResult.resolved_ip}</span> - firewall rules will target this address
                </div>
              )}
              <button style={{...s.btn, background:'#da3633', width:'100%'}}
                onClick={() => handleProtect({
                  indicator_value: lookupResult.query,
                  indicator_type: lookupResult.indicator_type,
                  threat_score: 0,
                  tags: [],
                  source: 'lookup',
                  description: lookupResult.resolved_ip ? `Resolves to ${lookupResult.resolved_ip}` : ''
                })}>
                Protect - Generate Snort/YARA Rules for "{lookupResult.query}"
                {lookupResult.resolved_ip && ` (${lookupResult.resolved_ip})`}
              </button>
            </div>
          </div>
        )}

        {/* Breach results */}
        {breachError && (
          <div style={{...s.section, background:'#2a1a1a', border:'1px solid #e74c3c', color:'#e74c3c', fontSize:13}}>
            {breachError}
          </div>
        )}
        {breachResult && (
          <div style={s.section}>
            <div style={{
              background: breachResult.total_breaches > 0 ? '#2a1a1a' : '#1a2e1a',
              border: `1px solid ${breachResult.total_breaches > 0 ? '#e74c3c' : '#2ecc71'}`,
              borderRadius:8, padding:'14px 18px', marginBottom:12
            }}>
              {(() => {
                const xonCount = breachResult.xposedornot?.breaches?.length || 0;
                const hibpCount = breachResult.total_breaches || 0;
                const hasBreaches = hibpCount > 0 || xonCount > 0;
                return (
                  <div style={{fontSize:20, fontWeight:700, color: hasBreaches ? '#e74c3c' : '#2ecc71'}}>
                    {hasBreaches
                      ? `${breachResult.email} found in breaches!`
                      : `${breachResult.email} - No breaches found`}
                  </div>
                );
              })()}
              {breachResult.total_pastes > 0 && (
                <div style={{color:'#8b949e', fontSize:13, marginTop:4}}>
                  Also found in {breachResult.total_pastes} paste{breachResult.total_pastes !== 1 ? 's' : ''}
                </div>
              )}
            </div>
            {/* HIBP status */}
            {breachResult.hibp_error && (
              <div style={{background:'#1a1a2e', border:'1px solid #30363d', borderRadius:8, padding:'10px 14px', marginBottom:10, fontSize:12, color:'#8b949e'}}>
                HIBP: {breachResult.hibp_error}
              </div>
            )}

            {/* HIBP breach cards */}
            {breachResult.breaches.length > 0 && (
              <div style={{marginBottom:12}}>
                <div style={{fontSize:12, fontWeight:600, color:'#58a6ff', marginBottom:8, textTransform:'uppercase', letterSpacing:'0.04em'}}>Have I Been Pwned</div>
                {breachResult.breaches.map((b, i) => (
                  <div key={i} style={{background:'#0d1117', border:'1px solid #30363d', borderRadius:8, padding:'14px 16px', marginBottom:8}}>
                    <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8}}>
                      <div style={{fontSize:15, fontWeight:600, color:'#e6edf3'}}>{b.Name}</div>
                      <div style={{fontSize:12, color:'#8b949e'}}>{b.BreachDate}</div>
                    </div>
                    <div style={{fontSize:12, color:'#8b949e', marginBottom:8, lineHeight:1.5}}
                      dangerouslySetInnerHTML={{__html: b.Description}}/>
                    <div style={{display:'flex', gap:6, flexWrap:'wrap', alignItems:'center'}}>
                      <span style={{fontSize:12, color:'#8b949e'}}>{(b.PwnCount || 0).toLocaleString()} accounts</span>
                      {(b.DataClasses || []).slice(0, 6).map(dc => (
                        <span key={dc} style={{
                          ...s.tag,
                          background: dc.toLowerCase().includes('password') ? '#3a1a1a' : '#21262d',
                          color: dc.toLowerCase().includes('password') ? '#e74c3c' : '#8b949e'
                        }}>{dc}</span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* XposedOrNot results */}
            {breachResult.xposedornot && !breachResult.xposedornot.error && breachResult.xposedornot.breaches.length > 0 && (
              <div style={{marginBottom:12}}>
                <div style={{fontSize:12, fontWeight:600, color:'#e67e22', marginBottom:8, textTransform:'uppercase', letterSpacing:'0.04em'}}>
                  XposedOrNot - {breachResult.xposedornot.breaches.length} breach{breachResult.xposedornot.breaches.length !== 1 ? 'es' : ''}
                </div>
                <div style={{display:'flex', gap:6, flexWrap:'wrap'}}>
                  {breachResult.xposedornot.breaches.map((b, i) => (
                    <span key={i} style={{background:'#1a1a2e', border:'1px solid #30363d', borderRadius:6, padding:'6px 12px', fontSize:12, color:'#e6edf3'}}>
                      {typeof b === 'string' ? b : (b.domain || b.name || JSON.stringify(b))}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* EmailRep results */}
            {breachResult.emailrep && !breachResult.emailrep.error && (
              <div style={{marginBottom:12}}>
                <div style={{fontSize:12, fontWeight:600, color:'#9b59b6', marginBottom:8, textTransform:'uppercase', letterSpacing:'0.04em'}}>EmailRep - Reputation Analysis</div>
                <div style={{background:'#0d1117', border:'1px solid #30363d', borderRadius:8, padding:'14px 16px'}}>
                  <div style={{display:'flex', gap:12, flexWrap:'wrap', marginBottom:8}}>
                    <div>
                      <span style={{color:'#8b949e', fontSize:12}}>Reputation: </span>
                      <span style={{
                        fontWeight:600, fontSize:13,
                        color: breachResult.emailrep.reputation === 'high' ? '#2ecc71'
                          : breachResult.emailrep.reputation === 'medium' ? '#f1c40f'
                          : breachResult.emailrep.reputation === 'low' ? '#e67e22' : '#e74c3c'
                      }}>{breachResult.emailrep.reputation}</span>
                    </div>
                    <div>
                      <span style={{color:'#8b949e', fontSize:12}}>Suspicious: </span>
                      <span style={{fontWeight:600, fontSize:13, color: breachResult.emailrep.suspicious ? '#e74c3c' : '#2ecc71'}}>
                        {breachResult.emailrep.suspicious ? 'Yes' : 'No'}
                      </span>
                    </div>
                    <div>
                      <span style={{color:'#8b949e', fontSize:12}}>References: </span>
                      <span style={{fontSize:13, color:'#e6edf3'}}>{breachResult.emailrep.references}</span>
                    </div>
                  </div>
                  <div style={{display:'flex', gap:6, flexWrap:'wrap'}}>
                    {breachResult.emailrep.credentials_leaked && (
                      <span style={{...s.tag, background:'#3a1a1a', color:'#e74c3c'}}>Credentials Leaked</span>
                    )}
                    {breachResult.emailrep.data_breach && (
                      <span style={{...s.tag, background:'#3a1a1a', color:'#e74c3c'}}>Data Breach</span>
                    )}
                    {breachResult.emailrep.malicious_activity && (
                      <span style={{...s.tag, background:'#3a1a1a', color:'#e74c3c'}}>Malicious Activity</span>
                    )}
                    {breachResult.emailrep.spam && (
                      <span style={{...s.tag, background:'#2a2a1a', color:'#f1c40f'}}>Spam</span>
                    )}
                    {breachResult.emailrep.deliverable === true && (
                      <span style={{...s.tag, background:'#1a2e1a', color:'#2ecc71'}}>Deliverable</span>
                    )}
                    {breachResult.emailrep.deliverable === false && (
                      <span style={{...s.tag, background:'#2a1a1a', color:'#e74c3c'}}>Not Deliverable</span>
                    )}
                  </div>
                  {breachResult.emailrep.profiles && breachResult.emailrep.profiles.length > 0 && (
                    <div style={{marginTop:8}}>
                      <span style={{color:'#8b949e', fontSize:12}}>Profiles found: </span>
                      {breachResult.emailrep.profiles.map((p, i) => (
                        <span key={i} style={s.tag}>{p}</span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* AI Summary results */}
        {aiSummaryError && (
          <div style={{...s.section, background:'#2a1a1a', border:'1px solid #e74c3c', color:'#e74c3c', fontSize:13}}>
            {aiSummaryError}
          </div>
        )}
        {aiSummary && (
          <div style={{...s.section, border:'1px solid #8957e5'}}>
            <div style={{display:'flex', gap:8, marginBottom:12}}>
              <span style={{background:'#8957e5', color:'#fff', padding:'2px 10px', borderRadius:12, fontSize:11, fontWeight:600}}>AI-GENERATED BRIEFING</span>
              {aiProvider && <span style={{background:'#21262d', color:'#8b949e', padding:'2px 10px', borderRadius:12, fontSize:11, border:'1px solid #30363d'}}>Powered by {aiProvider}</span>}
            </div>
            <div style={{lineHeight:1.7, fontSize:14, whiteSpace:'pre-wrap'}}
              dangerouslySetInnerHTML={{__html:
                aiSummary
                  .replace(/\*\*(.*?)\*\*/g, '<strong style="color:#58a6ff">$1</strong>')
                  .replace(/\n/g, '<br/>')
              }}/>
          </div>
        )}

        {/*  CHARTS (compact)  */}
        <div style={s.chartsRow}>
          <div style={s.chartBox}>
            <div style={s.chartLabel}>Score Distribution</div>
            <ResponsiveContainer width="100%" height={140}>
              <BarChart data={scoreData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#333"/>
                <XAxis dataKey="score" stroke="#666" tick={{fontSize:10}}/>
                <YAxis stroke="#666" tick={{fontSize:10}}/>
                <Tooltip contentStyle={{background:'#1e1e1e', border:'1px solid #444', fontSize:12}}/>
                <Bar dataKey="count" radius={[3,3,0,0]}>
                  {scoreData.map((entry, i) => (
                    <Cell key={i} fill={scoreColour(parseInt(entry.score))}/>
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div style={s.chartBox}>
            <div style={s.chartLabel}>Collection Sources</div>
            <ResponsiveContainer width="100%" height={140}>
              <PieChart>
                <Pie data={sourceData} cx="50%" cy="50%" outerRadius={55} dataKey="value"
                  label={({name, percent}) => `${name} ${(percent*100).toFixed(0)}%`}>
                  {sourceData.map((_, i) => (
                    <Cell key={i} fill={PIE_COLOURS[i % PIE_COLOURS.length]}/>
                  ))}
                </Pie>
                <Tooltip contentStyle={{background:'#1e1e1e', border:'1px solid #444', fontSize:12}}/>
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div style={{...s.chartBox, display:'flex', flexDirection:'column', justifyContent:'center'}}>
            <div style={s.chartLabel}>How This Dashboard Works</div>
            <div style={{fontSize:12, color:'#8b949e', lineHeight:1.7}}>
              <strong style={{color:'#58a6ff'}}>Collect</strong>: Threat data is gathered from URLhaus, AbuseIPDB, and OTX into your local database.<br/>
              <strong style={{color:'#e67e22'}}>Analyse</strong>: Each indicator is scored 0-100 based on severity, tags, and activity status.<br/>
              <strong style={{color:'#e74c3c'}}>Investigate</strong>: Use the tools above to search any indicator across 7 live sources.<br/>
              <strong style={{color:'#2ecc71'}}>Respond</strong>: Click Protect on any threat to generate Snort/YARA rules instantly.
            </div>
          </div>
        </div>

        {/*  BULK PROTECT  */}
        <div style={s.section}>
          <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:14}}>
            <div>
              <h2 style={{margin:0, fontSize:16, color:'#e6edf3'}}>Bulk Protect</h2>
              <p style={{margin:'4px 0 0', fontSize:12, color:'#8b949e'}}>
                Generate combined Snort, YARA, and firewall rules for all threats in a time period
              </p>
            </div>
          </div>
          <div style={{display:'flex', gap:10, flexWrap:'wrap', alignItems:'center', marginBottom:12}}>
            <div>
              <label style={{fontSize:11, color:'#8b949e', display:'block', marginBottom:4}}>Time period</label>
              <select style={s.select} value={bulkPeriod} onChange={e => setBulkPeriod(e.target.value)}>
                <option value="12hr">Last 12 hours</option>
                <option value="1day">Last 24 hours</option>
                <option value="1week">Last 7 days</option>
                <option value="1month">Last 30 days</option>
                <option value="all">All time</option>
              </select>
            </div>
            <div>
              <label style={{fontSize:11, color:'#8b949e', display:'block', marginBottom:4}}>Min score</label>
              <select style={s.select} value={bulkMinScore} onChange={e => setBulkMinScore(parseInt(e.target.value))}>
                <option value="0">All scores</option>
                <option value="15">15+</option>
                <option value="25">25+</option>
                <option value="30">30+</option>
                <option value="40">40+</option>
              </select>
            </div>
            <div>
              <label style={{fontSize:11, color:'#8b949e', display:'block', marginBottom:4}}>Mode</label>
              <div style={{display:'flex', gap:0}}>
                <button style={{
                  padding:'8px 14px', fontSize:13, border:'1px solid #30363d', cursor:'pointer',
                  borderRadius:'6px 0 0 6px', fontWeight:600,
                  background: bulkMode === 'template' ? '#da3633' : '#21262d',
                  color: bulkMode === 'template' ? '#fff' : '#8b949e'
                }} onClick={() => setBulkMode('template')}>Instant</button>
                <button style={{
                  padding:'8px 14px', fontSize:13, border:'1px solid #30363d', borderLeft:'none', cursor:'pointer',
                  borderRadius:'0 6px 6px 0', fontWeight:600,
                  background: bulkMode === 'ai' ? '#8957e5' : '#21262d',
                  color: bulkMode === 'ai' ? '#fff' : '#8b949e'
                }} onClick={() => setBulkMode('ai')}>AI-Enhanced</button>
              </div>
            </div>
            <div style={{alignSelf:'flex-end'}}>
              <button style={{...s.btn, background: bulkLoading ? '#333' : '#da3633'}}
                onClick={handleBulkProtect} disabled={bulkLoading}>
                {bulkLoading ? 'Generating...' : 'Generate Bulk Rules'}
              </button>
            </div>
          </div>

          {bulkResult && bulkResult.error && (
            <div style={{background:'#2a1a1a', border:'1px solid #e74c3c', borderRadius:8, padding:'10px 14px', color:'#e74c3c', fontSize:13}}>
              {bulkResult.error}
            </div>
          )}

          {bulkResult && !bulkResult.error && (
            <div>
              <div style={{display:'flex', gap:8, alignItems:'center', marginBottom:12}}>
                <span style={{background: bulkResult.mode === 'ai' ? '#8957e5' : '#da3633', color:'#fff', padding:'2px 10px', borderRadius:12, fontSize:11, fontWeight:600}}>
                  {bulkResult.mode === 'ai' ? `AI-GENERATED (${bulkResult.provider})` : 'TEMPLATE RULES'}
                </span>
                <span style={{color:'#8b949e', fontSize:13}}>
                  {bulkResult.indicator_count} indicators | Period: {bulkResult.period}
                </span>
                {bulkResult.stats && (
                  <span style={{color:'#8b949e', fontSize:12}}>
                    | {bulkResult.stats.unique_ips} IPs, {bulkResult.stats.unique_domains} domains, {bulkResult.stats.snort_rules} Snort rules
                  </span>
                )}
              </div>
              <div style={{background:'#0d1117', border:'1px solid #30363d', borderRadius:8, padding:'16px 20px', fontFamily:'monospace', fontSize:12, lineHeight:1.6, color:'#e6edf3', whiteSpace:'pre-wrap', maxHeight:400, overflowY:'auto'}}>
                {bulkResult.script}
              </div>
              <div style={{display:'flex', gap:8, marginTop:10}}>
                <button style={s.smallBtn} onClick={() => navigator.clipboard.writeText(bulkResult.script)}>
                  Copy Script
                </button>
                {bulkResult.yara && (
                  <button style={s.smallBtn} onClick={() => navigator.clipboard.writeText(bulkResult.yara)}>
                    Copy YARA Rules
                  </button>
                )}
                <button style={s.smallBtn} onClick={() => {
                  const blob = new Blob([bulkResult.script], {type:'text/plain'});
                  const a = document.createElement('a');
                  a.href = URL.createObjectURL(blob);
                  a.download = `osint-rules-${bulkResult.period}.txt`;
                  a.click();
                }}>
                  Download Script
                </button>
                {bulkResult.yara && (
                  <button style={s.smallBtn} onClick={() => {
                    const blob = new Blob([bulkResult.yara], {type:'text/plain'});
                    const a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    a.download = `osint-yara-${bulkResult.period}.yar`;
                    a.click();
                  }}>
                    Download YARA
                  </button>
                )}
              </div>
            </div>
          )}
        </div>

        {/*  THREAT TABLE  */}
        <div style={s.section}>
          <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:12}}>
            <h2 style={{margin:0, fontSize:16, color:'#e6edf3'}}>Threat Database</h2>
            <span style={{color:'#8b949e', fontSize:13}}>
              Showing {filtered.length} of {threats.length}
            </span>
          </div>
          <div style={{display:'flex', gap:10, marginBottom:12, flexWrap:'wrap'}}>
            <input
              style={{...s.input, minWidth:180, flex:1}}
              placeholder="Search indicators..."
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(1); }}
            />
            <select style={s.select} value={typeFilter} onChange={e => { setTypeFilter(e.target.value); setPage(1); }}>
              <option value="">All types</option>
              <option value="url">URL</option>
              <option value="ip">IP</option>
              <option value="domain">Domain</option>
              <option value="hash">Hash</option>
            </select>
            <select style={s.select} value={sourceFilter} onChange={e => { setSourceFilter(e.target.value); setPage(1); }}>
              <option value="">All sources</option>
              {[...new Set(threats.map(t => t.source))].sort().map(src => (
                <option key={src} value={src}>{src}</option>
              ))}
            </select>
            <select style={s.select} value={sortBy} onChange={e => { setSortBy(e.target.value); setPage(1); }}>
              <option value="score">Highest score</option>
              <option value="newest">Newest first</option>
              <option value="oldest">Oldest first</option>
            </select>
          </div>
          <div style={{overflowX:'auto', border:'1px solid #30363d', borderRadius:8}}>
            <table style={s.table}>
              <thead>
                <tr>
                  {['Indicator','Type','Source','Score','Tags','First seen',''].map(h => (
                    <th key={h || '_act'} style={s.th}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {paged.map(t => (
                  <tr key={t.id} style={s.tr}>
                    <td style={{...s.td, fontFamily:'monospace', fontSize:12, maxWidth:260,
                      overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', color:'#e6edf3'}}>
                      {t.indicator_value}
                    </td>
                    <td style={s.td}><span style={s.typeBadge}>{t.indicator_type}</span></td>
                    <td style={s.td}>{t.source}</td>
                    <td style={s.td}>
                      <span style={{...s.pill, background: scoreColour(t.threat_score)}}>{t.threat_score}</span>
                    </td>
                    <td style={s.td}>
                      {(t.tags || []).slice(0,3).map(tag => (
                        <span key={tag} style={s.tag}>{tag}</span>
                      ))}
                    </td>
                    <td style={{...s.td, fontSize:12, color:'#888'}}>
                      {t.first_seen ? new Date(t.first_seen).toLocaleDateString() : '-'}
                    </td>
                    <td style={s.td}>
                      <button style={s.protectBtn} onClick={() => handleProtect(t)}>Protect</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div style={{display:'flex', justifyContent:'center', alignItems:'center', gap:6, marginTop:14}}>
              <button style={{...s.smallBtn, opacity: page === 1 ? 0.4 : 1}}
                disabled={page === 1} onClick={() => setPage(1)}>First</button>
              <button style={{...s.smallBtn, opacity: page === 1 ? 0.4 : 1}}
                disabled={page === 1} onClick={() => setPage(p => p - 1)}>Prev</button>
              {Array.from({length: totalPages}, (_, i) => i + 1)
                .filter(p => p === 1 || p === totalPages || Math.abs(p - page) <= 2)
                .reduce((acc, p, i, arr) => {
                  if (i > 0 && p - arr[i-1] > 1) acc.push('...');
                  acc.push(p);
                  return acc;
                }, [])
                .map((p, i) => p === '...'
                  ? <span key={`dot-${i}`} style={{color:'#8b949e', fontSize:12}}>...</span>
                  : <button key={p} style={{
                      ...s.smallBtn,
                      background: p === page ? '#1f6feb' : '#21262d',
                      color: p === page ? '#fff' : '#8b949e',
                      minWidth:36, textAlign:'center'
                    }} onClick={() => setPage(p)}>{p}</button>
                )}
              <button style={{...s.smallBtn, opacity: page === totalPages ? 0.4 : 1}}
                disabled={page === totalPages} onClick={() => setPage(p => p + 1)}>Next</button>
              <button style={{...s.smallBtn, opacity: page === totalPages ? 0.4 : 1}}
                disabled={page === totalPages} onClick={() => setPage(totalPages)}>Last</button>
              <span style={{color:'#8b949e', fontSize:12, marginLeft:8}}>
                Page {page} of {totalPages}
              </span>
            </div>
          )}
        </div>
        </>)}
      </div>

      {/* API Keys Modal */}
      {showKeyModal && (
        <div style={s.overlay} onClick={(e) => { if (e.target === e.currentTarget) setShowKeyModal(false); }}>
          <div style={s.modal}>
            <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:16}}>
              <h2 style={{margin:0, fontSize:18, color:'#e6edf3'}}>API Key Settings</h2>
              <button style={s.closeBtn} onClick={() => setShowKeyModal(false)}>x</button>
            </div>
            <p style={{color:'#8b949e', fontSize:13, margin:'0 0 20px', lineHeight:1.5}}>
              Keys are encrypted with AES-128 and stored server-side. They are never exposed to the browser after saving.
            </p>
            {[
              { id: 'gemini',     label: 'Google Gemini',       placeholder: 'AIza...',                 desc: 'Primary AI - summaries and rule generation' },
              { id: 'groq',       label: 'Groq',                placeholder: 'gsk_...',                 desc: 'Fallback AI if Gemini is unavailable' },
              { id: 'hibp',       label: 'Have I Been Pwned',   placeholder: 'Your HIBP key',           desc: 'Email breach lookups' },
              { id: 'abuseipdb',  label: 'AbuseIPDB',           placeholder: 'Your AbuseIPDB key',      desc: 'IP reputation and abuse reports' },
              { id: 'otx',        label: 'AlienVault OTX',      placeholder: 'Your OTX key',            desc: 'Threat intelligence feeds and campaigns' },
              { id: 'urlhaus',    label: 'URLhaus',             placeholder: 'Your URLhaus Auth-Key',   desc: 'Malware URL feed (abuse.ch)' },
              { id: 'virustotal', label: 'VirusTotal',          placeholder: 'Your VirusTotal key',     desc: 'File/URL detection across antivirus engines' },
              { id: 'shodan',     label: 'Shodan',              placeholder: 'Your Shodan key',         desc: 'Open ports, services, vulnerabilities' },
              { id: 'securitytrails', label: 'SecurityTrails',  placeholder: 'Your SecurityTrails key', desc: 'DNS records and subdomain discovery' },
              { id: 'intelx',     label: 'IntelligenceX',       placeholder: 'Your IntelX key',         desc: 'Dark web, paste sites, leaked databases' },
            ].map(svc => (
              <div key={svc.id} style={s.keyRow}>
                <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:6}}>
                  <div>
                    <div style={{fontSize:14, fontWeight:600, color:'#e6edf3'}}>{svc.label}</div>
                    <div style={{fontSize:11, color:'#8b949e'}}>{svc.desc}</div>
                  </div>
                  <div style={{display:'flex', gap:6, alignItems:'center'}}>
                    {savedServices.includes(svc.id) && (
                      <span style={{fontSize:11, fontWeight:600, padding:'2px 8px', borderRadius:10, background:'#1a2e1a', color:'#2ecc71', border:'1px solid #2ecc71'}}>Saved</span>
                    )}
                    {keyStatus[svc.id] && keyStatus[svc.id] !== 'saved' && (
                      <span style={{fontSize:11, fontWeight:600, padding:'2px 8px', borderRadius:10,
                        background: keyStatus[svc.id] === 'valid' ? '#1a2e1a' : '#2a1a1a',
                        color: keyStatus[svc.id] === 'valid' ? '#2ecc71' : '#e74c3c',
                        border: `1px solid ${keyStatus[svc.id] === 'valid' ? '#2ecc71' : '#e74c3c'}`
                      }}>{keyStatus[svc.id] === 'valid' ? 'Valid' : 'Invalid'}</span>
                    )}
                  </div>
                </div>
                <div style={{display:'flex', gap:8}}>
                  <input type="password"
                    style={{...s.input, flex:1, fontSize:13, minWidth:0, fontFamily:'monospace'}}
                    placeholder={savedServices.includes(svc.id) ? '(key saved on server)' : svc.placeholder}
                    value={keyInputs[svc.id] || ''}
                    onChange={e => setKeyInputs(prev => ({...prev, [svc.id]: e.target.value}))}
                  />
                  <button style={s.smallBtn} onClick={() => validateKey(svc.id)}
                    disabled={validatingKey === svc.id || !keyInputs[svc.id]}>
                    {validatingKey === svc.id ? 'Testing...' : 'Test'}
                  </button>
                  <button style={{...s.smallBtn, background:'#238636', border:'none', color:'#fff', opacity: keyInputs[svc.id] ? 1 : 0.5}}
                    onClick={() => saveKey(svc.id)} disabled={savingKey === svc.id || !keyInputs[svc.id]}>
                    {savingKey === svc.id ? 'Saving...' : 'Save'}
                  </button>
                  {savedServices.includes(svc.id) && (
                    <button style={{...s.smallBtn, background:'#da3633', border:'none', color:'#fff'}}
                      onClick={() => removeKey(svc.id)}>Remove</button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Protect - Rules Modal */}
      {rulesModal && (
        <div style={s.overlay} onClick={(e) => { if (e.target === e.currentTarget) setRulesModal(null); }}>
          <div style={{...s.modal, maxWidth:800}}>
            <div style={{display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:16}}>
              <div>
                <h2 style={{margin:0, fontSize:18, color:'#e6edf3'}}>Protect - Security Rules</h2>
                <div style={{fontFamily:'monospace', fontSize:13, color:'#58a6ff', marginTop:6, wordBreak:'break-all'}}>
                  {rulesModal.indicator_value}
                </div>
                <div style={{display:'flex', gap:8, marginTop:8}}>
                  <span style={s.typeBadge}>{rulesModal.indicator_type}</span>
                  <span style={{...s.pill, background: scoreColour(rulesModal.threat_score)}}>Score: {rulesModal.threat_score}</span>
                  <span style={{color:'#8b949e', fontSize:12}}>{rulesModal.source}</span>
                </div>
              </div>
              <button style={s.closeBtn} onClick={() => setRulesModal(null)}>x</button>
            </div>

            <div style={{display:'flex', gap:0, marginBottom:16, borderBottom:'1px solid #30363d'}}>
              <button style={{
                background: rulesMode === 'template' ? '#21262d' : 'transparent',
                color: rulesMode === 'template' ? '#e6edf3' : '#8b949e',
                border:'none', borderBottom: rulesMode === 'template' ? '2px solid #58a6ff' : '2px solid transparent',
                padding:'10px 20px', fontSize:13, fontWeight:600, cursor:'pointer'
              }} onClick={() => setRulesMode('template')}>Instant Rules</button>
              <button style={{
                background: rulesMode === 'ai' ? '#21262d' : 'transparent',
                color: rulesMode === 'ai' ? '#e6edf3' : '#8b949e',
                border:'none', borderBottom: rulesMode === 'ai' ? '2px solid #8957e5' : '2px solid transparent',
                padding:'10px 20px', fontSize:13, fontWeight:600, cursor:'pointer'
              }} onClick={() => { if (rulesMode !== 'ai') handleAiRules(); }}>AI-Enhanced Rules</button>
            </div>

            {rulesMode === 'template' && (
              rulesLoading ? <div style={{textAlign:'center', padding:30, color:'#8b949e'}}>Loading rules...</div>
              : rulesTemplate && !rulesTemplate.error ? (
                <div>
                  <div style={{background:'#1a2e1a', border:'1px solid #2ecc71', borderRadius:8, padding:'12px 16px', marginBottom:14, fontSize:13, color:'#2ecc71'}}>
                    <strong>Firewall:</strong> {rulesTemplate.firewall}
                  </div>
                  {[{label:'Snort Rule', val:rulesTemplate.snort}, {label:'YARA Rule', val:rulesTemplate.yara}].map(r => (
                    <div key={r.label} style={{marginBottom:14}}>
                      <div style={{fontSize:12, fontWeight:600, color:'#58a6ff', marginBottom:6, textTransform:'uppercase', letterSpacing:'0.05em'}}>{r.label}</div>
                      <div style={{background:'#0d1117', border:'1px solid #30363d', borderRadius:8, padding:'14px 16px', fontFamily:'monospace', fontSize:12, lineHeight:1.6, color:'#e6edf3', whiteSpace:'pre-wrap', wordBreak:'break-all'}}>{r.val}</div>
                      <button style={{...s.smallBtn, marginTop:6}} onClick={() => navigator.clipboard.writeText(r.val)}>Copy {r.label}</button>
                    </div>
                  ))}
                  <button style={s.smallBtn} onClick={() => navigator.clipboard.writeText(
                    `# Snort Rule\n${rulesTemplate.snort}\n\n# YARA Rule\n${rulesTemplate.yara}\n\n# Firewall\n${rulesTemplate.firewall}`
                  )}>Copy All Rules</button>
                </div>
              ) : rulesTemplate?.error ? (
                <div style={{color:'#e74c3c', fontSize:13, padding:16}}>Error: {rulesTemplate.error}</div>
              ) : null
            )}

            {rulesMode === 'ai' && (
              rulesLoading ? (
                <div style={{textAlign:'center', padding:40, color:'#8b949e'}}>
                  <div style={{fontSize:14, marginBottom:8}}>Generating AI-enhanced rules...</div>
                  <div style={{fontSize:12}}>This may take a few seconds</div>
                </div>
              ) : rulesContent ? (
                <div>
                  <div style={{display:'inline-block', background:'#8957e5', color:'#fff', padding:'2px 10px', borderRadius:12, fontSize:11, fontWeight:600, marginBottom:12}}>AI-GENERATED</div>
                  <div style={{background:'#0d1117', border:'1px solid #30363d', borderRadius:8, padding:'16px 20px', fontFamily:'monospace', fontSize:13, lineHeight:1.7, color:'#e6edf3', whiteSpace:'pre-wrap', overflowX:'auto'}}
                    dangerouslySetInnerHTML={{__html:
                      rulesContent
                        .replace(/\*\*(.*?)\*\*/g, '<strong style="color:#58a6ff">$1</strong>')
                        .replace(/```(\w*)\n([\s\S]*?)```/g, '<div style="background:#1a1e24;border:1px solid #21262d;border-radius:6px;padding:12px;margin:8px 0;overflow-x:auto"><code>$2</code></div>')
                        .replace(/\n/g, '<br/>')
                    }}/>
                  <button style={{...s.smallBtn, marginTop:12}} onClick={() => navigator.clipboard.writeText(rulesContent)}>Copy to clipboard</button>
                </div>
              ) : null
            )}
          </div>
        </div>
      )}
    </div>
  );
}

const makeStyles = (isMobile) => ({
  page:      { background:'#0d1117', minHeight:'100vh', color:'#e6edf3', fontFamily:'-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif' },
  loading:   { display:'flex', alignItems:'center', justifyContent:'center', height:'100vh', color:'#888', fontSize:18 },

  // Header
  header:      { background:'#161b22', borderBottom:'1px solid #30363d', padding: isMobile ? '16px 14px' : '20px 32px' },
  headerTitle: { margin:0, fontSize: isMobile ? 26 : 44, fontWeight:800, letterSpacing:'-0.5px' },
  headerSub:   { margin:'4px 0 0', color:'#8b949e', fontSize:13 },
  keyBtn:      { background:'#21262d', border:'1px solid #30363d', color:'#e6edf3', borderRadius:8, padding:'8px 16px', fontSize:13, cursor:'pointer', display:'flex', alignItems:'center', gap:8 },
  keyBadge:    { background:'#2ecc71', color:'#fff', borderRadius:10, padding:'1px 7px', fontSize:11, fontWeight:600 },
  keyBtnPos:   isMobile ? { position:'static', margin:'12px auto 0' } : { position:'absolute', top:0, right:0 },

  // Stats bar
  statsBar:   { display:'flex', gap:0, marginTop:16, background:'#0d1117', borderRadius:8, border:'1px solid #30363d', overflow:'hidden', flexWrap:'wrap' },
  statItem:   { padding: isMobile ? '8px 10px' : '10px 18px', display:'flex', flexDirection:'column', alignItems:'center', flex:1, minWidth:80 },
  statNum:    { fontSize:20, fontWeight:700, color:'#58a6ff' },
  statLabel:  { fontSize:11, color:'#8b949e', marginTop:2, textTransform:'uppercase', letterSpacing:'0.03em' },
  statDivider:{ width:1, background:'#30363d', alignSelf:'stretch' },

  // Content area
  content: { padding: isMobile ? '16px 14px' : '20px 32px' },

  // Tool grid
  toolGrid:   { display:'grid', gridTemplateColumns: isMobile ? '1fr' : 'repeat(auto-fit, minmax(300px, 1fr))', gap:16, marginBottom:20 },
  toolCard:   { background:'#161b22', border:'1px solid #30363d', borderTop:'3px solid #1f6feb', borderRadius:8, padding:20 },
  toolHeader: { display:'flex', gap:12, alignItems:'flex-start', marginBottom:12 },
  toolIcon:   { display:'flex', alignItems:'center', justifyContent:'center', width:36, height:36, borderRadius:8, color:'#fff', fontWeight:700, fontSize:14, flexShrink:0 },
  toolName:   { fontSize:15, fontWeight:600, color:'#e6edf3' },
  toolDesc:   { fontSize:12, color:'#8b949e', marginTop:2, lineHeight:1.4 },
  toolSources:{ display:'flex', gap:4, flexWrap:'wrap', marginBottom:12 },
  sourcePill: { background:'#21262d', color:'#8b949e', padding:'2px 8px', borderRadius:10, fontSize:10, border:'1px solid #30363d' },

  // Inputs & buttons
  input:    { background:'#0d1117', border:'1px solid #30363d', borderRadius:6, padding:'8px 12px', color:'#e6edf3', fontSize:14 },
  select:   { background:'#0d1117', border:'1px solid #30363d', borderRadius:6, padding:'8px 12px', color:'#e6edf3', fontSize:14 },
  btn:      { color:'#fff', border:'none', borderRadius:6, padding:'8px 20px', fontSize:14, cursor:'pointer', fontWeight:600, whiteSpace:'nowrap' },
  smallBtn: { background:'#21262d', border:'1px solid #30363d', color:'#e6edf3', borderRadius:6, padding:'6px 12px', fontSize:12, cursor:'pointer', whiteSpace:'nowrap' },

  // Sections
  section:       { background:'#161b22', border:'1px solid #30363d', borderRadius:8, padding:20, marginBottom:20 },
  sectionHeader: { marginBottom:12 },
  sectionTitle:  { margin:0, fontSize:16, color:'#e6edf3', display:'flex', alignItems:'center' },

  // Live result cards
  liveGrid:    { display:'grid', gridTemplateColumns: isMobile ? '1fr' : 'repeat(auto-fit, minmax(320px, 1fr))', gap:10, marginBottom:10 },
  liveCard:    { background:'#0d1117', border:'1px solid #30363d', borderRadius:8, padding:'14px 16px' },
  lcHeader:    { display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8 },
  lcTitle:     { fontSize:13, fontWeight:600, color:'#58a6ff' },
  lcGrid:      { display:'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr', gap:'4px 16px', fontSize:12 },
  lcLabel:     { color:'#8b949e' },

  // Result row
  resultRow: { display:'flex', gap:8, alignItems:'center', flexWrap:'wrap', padding:'8px 12px', background:'#0d1117', border:'1px solid #30363d', borderRadius:6, marginBottom:6 },

  // Charts
  chartsRow: { display:'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr 1.2fr', gap:16, marginBottom:20 },
  chartBox:  { background:'#161b22', border:'1px solid #30363d', borderRadius:8, padding:'14px 16px' },
  chartLabel:{ fontSize:12, color:'#8b949e', fontWeight:600, marginBottom:8, textTransform:'uppercase', letterSpacing:'0.04em' },

  // Table
  table: { width:'100%', borderCollapse:'collapse', fontSize:13 },
  th:    { background:'#161b22', padding:'10px 14px', textAlign:'left', color:'#8b949e', fontWeight:600, borderBottom:'1px solid #30363d', whiteSpace:'nowrap' },
  tr:    { borderBottom:'1px solid #21262d' },
  td:    { padding:'10px 14px', verticalAlign:'middle' },

  // Badges & tags
  typeBadge: { background:'#1f6feb', color:'#58a6ff', padding:'2px 8px', borderRadius:12, fontSize:11 },
  pill:      { color:'#fff', padding:'2px 8px', borderRadius:12, fontSize:12, fontWeight:600 },
  tag:       { background:'#21262d', color:'#8b949e', padding:'2px 6px', borderRadius:4, fontSize:11, marginRight:4 },
  protectBtn:{ background:'#da3633', color:'#fff', border:'none', borderRadius:6, padding:'5px 14px', fontSize:12, cursor:'pointer', fontWeight:600, whiteSpace:'nowrap' },

  // Modals
  overlay:  { position:'fixed', top:0, left:0, right:0, bottom:0, background:'rgba(0,0,0,0.75)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1000, padding:20 },
  modal:    { background:'#161b22', border:'1px solid #30363d', borderRadius:12, padding: isMobile ? '18px 16px' : '24px 28px', maxWidth:560, width:'100%', maxHeight:'85vh', overflowY:'auto' },
  closeBtn: { background:'none', border:'1px solid #30363d', color:'#8b949e', fontSize:18, cursor:'pointer', borderRadius:6, padding:'4px 10px', lineHeight:1 },
  keyRow:   { background:'#0d1117', border:'1px solid #30363d', borderRadius:8, padding:'14px 16px', marginBottom:10 },
});
