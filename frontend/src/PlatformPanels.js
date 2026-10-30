import React, { useCallback, useEffect, useState } from 'react';

import { S as CYBER_S } from './cyberTheme';

// Legacy values are kept for any panel-specific keys; CYBERDECK theme
// values win for every shared key.
const LEGACY_S = {
  section: { display: 'flex', flexDirection: 'column', gap: 16 },
  card: { background: '#161b22', border: '1px solid #30363d', borderRadius: 10, padding: 16 },
  title: { margin: '0 0 8px', color: '#e6edf3', fontSize: 20 },
  sub: { color: '#8b949e', fontSize: 13, lineHeight: 1.55, margin: '0 0 12px' },
  row: { display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' },
  label: { color: '#8b949e', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em' },
  input: { background: '#0d1117', border: '1px solid #30363d', color: '#e6edf3', borderRadius: 6, padding: '8px 10px', fontSize: 13 },
  button: { background: '#1f6feb', border: '1px solid #1f6feb', color: '#fff', borderRadius: 6, padding: '8px 12px', fontSize: 12, fontWeight: 600, cursor: 'pointer' },
  ghost: { background: '#21262d', border: '1px solid #30363d', color: '#c9d1d9', borderRadius: 6, padding: '8px 12px', fontSize: 12, cursor: 'pointer' },
  stats: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(120px,1fr))', gap: 8 },
  stat: { background: '#0d1117', border: '1px solid #30363d', borderRadius: 8, padding: 10 },
  num: { color: '#e6edf3', fontSize: 20, fontWeight: 700 },
  statLabel: { color: '#8b949e', fontSize: 11, marginTop: 2 },
  phases: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(260px,1fr))', gap: 10 },
  phase: { background: '#0d1117', border: '1px solid #30363d', borderRadius: 8, padding: 12 },
  tag: { background: '#21262d', color: '#8b949e', border: '1px solid #30363d', borderRadius: 999, padding: '2px 8px', fontSize: 11 },
  mono: { background: '#0d1117', border: '1px solid #30363d', color: '#c9d1d9', borderRadius: 8, padding: 12, fontSize: 12, maxHeight: 460, overflow: 'auto', whiteSpace: 'pre-wrap' },
  error: { color: '#f85149' },
  ok: { color: '#3fb950' },

};
const S = { ...LEGACY_S, ...CYBER_S };

export function PlatformPanel({ api }) {
  const [overview, setOverview] = useState(null);
  const [output, setOutput] = useState(null);
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState('');
  const [caseId, setCaseId] = useState('0');
  const [probe, setProbe] = useState(false);
  const [workspace, setWorkspace] = useState('');

  const run = useCallback(async (label, fn) => {
    setBusy(true);
    setStatus(label + '…');
    try {
      const data = await fn();
      setOutput(data);
      setStatus(label + ' · ok');
    } catch (err) {
      const data = err?.response?.data || { error: err.message };
      setOutput(data);
      setStatus(label + ' · failed');
    }
    setBusy(false);
  }, []);

  const load = useCallback(() => run('phase overview', async () => {
    const res = await api.get('/platform/overview');
    setOverview(res.data);
    return res.data;
  }), [api, run]);

  useEffect(() => { load(); }, [load]);

  const phases = overview?.phases?.phases || [];
  const graph = overview?.analytics?.graph || {};
  const cov = overview?.analytics?.social_coverage || {};
  const runtime = overview?.runtime || {};

  return (
    <div style={S.section}>
      <div style={S.card}>
        <h2 style={S.title}>Platform phases 1–12</h2>
        <p style={S.sub}>
          Evidence graph, verified source health, social coverage, lightweight runtime, signed module packs,
          offline mode, security posture, team workspaces, performance, plugin SDK, compliance and observability.
          These endpoints are real; source counts remain registry-derived and are never padded.
        </p>
        <div style={S.stats}>
          {[
            ['phases', phases.length],
            ['entities', graph.entities || 0],
            ['artifacts', graph.artifacts || 0],
            ['timeline', graph.timeline_events || 0],
            ['workspaces', graph.workspaces || 0],
            ['direct name APIs', cov.direct_name_apis || 0],
            ['search link-outs', cov.public_search_link_out || 0],
            ['handle-only', cov.handle_only || 0],
          ].map(([label, value]) => (
            <div key={label} style={S.stat}>
              <div style={S.num}>{value}</div>
              <div style={S.statLabel}>{label}</div>
            </div>
          ))}
        </div>
        <div style={{ ...S.row, marginTop: 12 }}>
          <button style={S.button} onClick={load} disabled={busy}>Reload overview</button>
          <button style={S.ghost} onClick={() => run('self-test', () => api.post('/platform/runtime/self-test', {}))} disabled={busy}>Self-test</button>
          <button style={S.ghost} onClick={() => run('security posture', () => api.get('/platform/security/posture'))} disabled={busy}>Security posture</button>
          <button style={S.ghost} onClick={() => run('benchmark', () => api.post('/platform/performance/benchmark', { iterations: 20 }))} disabled={busy}>Benchmark</button>
          <button style={S.ghost} onClick={() => run('diagnostics', () => api.get('/platform/support/diagnostics'))} disabled={busy}>Diagnostics</button>
          <span style={{ ...S.sub, margin: 0, color: busy ? '#d29922' : '#8b949e' }}>{status}</span>
        </div>
        <div style={{ ...S.row, marginTop: 10 }}>
          <span style={S.tag}>v{runtime.version || '—'}</span>
          <span style={S.tag}>{runtime.frozen ? 'compiled' : 'source'}</span>
          <span style={S.tag}>{runtime.fts5 ? 'FTS5' : 'LIKE fallback'}</span>
          <span style={S.tag}>{runtime.offline ? 'offline' : 'online'}</span>
          <span style={S.tag}>budget {runtime.budgets?.query_ms || '—'} ms</span>
        </div>
      </div>

      <div style={S.card}>
        <h3 style={{ ...S.title, fontSize: 16 }}>Phase status</h3>
        <div style={S.phases}>
          {phases.map(p => (
            <div key={p.id} style={S.phase}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                <strong style={{ color: '#e6edf3', fontSize: 13 }}>{p.id}. {p.name}</strong>
                <span style={{ ...S.tag, color: p.status === 'implemented' ? '#3fb950' : '#d29922' }}>{p.status}</span>
              </div>
              <p style={{ ...S.sub, margin: '6px 0' }}>{(p.capabilities || []).join(' · ')}</p>
              <div style={S.row}>{(p.endpoints || []).map(e => <span key={e} style={S.tag}>{e}</span>)}</div>
            </div>
          ))}
        </div>
      </div>

      <div style={S.card}>
        <h3 style={{ ...S.title, fontSize: 16 }}>Graph, social recon & team</h3>
        <div style={S.row}>
          <div>
            <div style={S.label}>case id</div>
            <input style={{ ...S.input, width: 90 }} value={caseId} onChange={e => setCaseId(e.target.value)} />
          </div>
          <div>
            <div style={S.label}>social name</div>
            <input style={S.input} value={name} onChange={e => setName(e.target.value)} placeholder="Jane Doe" />
          </div>
          <label style={{ ...S.sub, display: 'flex', alignItems: 'center', gap: 6, margin: 0 }}>
            <input type="checkbox" checked={probe} onChange={e => setProbe(e.target.checked)} /> live probe
          </label>
          <button style={S.ghost} disabled={busy} onClick={() => run('graph bundle', () => api.get(`/platform/graph/bundle?case_id=${encodeURIComponent(caseId || '0')}`))}>Graph bundle</button>
          <button style={S.ghost} disabled={busy || !name.trim()} onClick={() => run('social recon', () => api.post('/platform/social/recon', {
            name: name.trim(), probe, case_id: Number(caseId || 0),
          }))}>Social recon</button>
        </div>
        <div style={{ ...S.row, marginTop: 10 }}>
          <div>
            <div style={S.label}>workspace name</div>
            <input style={S.input} value={workspace} onChange={e => setWorkspace(e.target.value)} placeholder="Case Alpha team" />
          </div>
          <button style={S.ghost} disabled={busy || !workspace.trim()} onClick={() => run('create workspace', () => api.post('/platform/workspaces', { name: workspace.trim() }))}>Create workspace</button>
          <button style={S.ghost} disabled={busy} onClick={() => run('workspaces', () => api.get('/platform/workspaces'))}>List workspaces</button>
          <button style={S.ghost} disabled={busy} onClick={() => run('social coverage', () => api.get('/platform/social/coverage'))}>Social coverage</button>
        </div>
        <pre style={{ ...S.mono, marginTop: 12 }}>{output ? JSON.stringify(output, null, 2) : 'No platform action yet.'}</pre>
      </div>
    </div>
  );
}

export default PlatformPanel;
