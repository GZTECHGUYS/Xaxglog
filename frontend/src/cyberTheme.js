/* Xaxglog CYBERDECK theme — sci-fi HUD skin for the operator console.
 *
 * Every panel file imports `S` from here (or merges it), so all look and
 * behaviour lives in one file. Components/JSX are untouched: it is a pure
 * re-skin through the same style keys.
 *
 * Design language:
 *   - deep-space darks (#05070f) with cyan HUD chrome (#00e5ff)
 *   - magenta/amber/green accents for signal colours
 *   - notched panels (clip-path), inner glow, scanline overlay (App.css)
 *   - terminal monospace everywhere, uppercase tracking on headings/labels
 */
export const C = {
  bg0: '#04060e',        // page black-blue
  bg1: '#070b18',        // panel base
  bg2: '#0a1122',        // card base
  line: 'rgba(0,229,255,0.28)',   // HUD border
  lineDim: 'rgba(0,229,255,0.14)',
  cyan: '#00e5ff',
  cyanHi: '#8bf9ff',
  magenta: '#ff2bd6',
  amber: '#ffb347',
  green: '#39ff88',
  red: '#ff3b5c',
  text: '#c9f6ff',
  dim: '#5b7f96',
  font: '"JetBrains Mono","Fira Code","Cascadia Code",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace',
};

const notch = (px = 14) => (
  `polygon(0 0, calc(100% - ${px}px) 0, 100% ${px}px, 100% 100%, ${px}px 100%, 0 calc(100% - ${px}px))`
);

export const S = {
  section: {
    background: `linear-gradient(165deg, rgba(10,18,40,0.92), rgba(5,9,20,0.96))`,
    border: `1px solid ${C.line}`,
    boxShadow: `0 0 18px rgba(0,229,255,0.10), inset 0 0 26px rgba(0,229,255,0.045)`,
    borderRadius: 0,
    clipPath: notch(),
    padding: 20,
    marginBottom: 22,
    position: 'relative',
  },
  card: {
    background: `linear-gradient(160deg, rgba(12,20,42,0.85), rgba(7,11,24,0.9))`,
    border: `1px solid ${C.lineDim}`,
    borderRadius: 0,
    padding: '13px 15px',
    marginBottom: 10,
    boxShadow: 'inset 0 0 14px rgba(0,229,255,0.05)',
  },
  title: {
    margin: '0 0 6px', fontSize: 15, color: C.cyanHi, textTransform: 'uppercase',
    letterSpacing: '2px', fontWeight: 700,
    textShadow: `0 0 12px rgba(0,229,255,0.55), 0 0 32px rgba(0,229,255,0.2)`,
    fontFamily: C.font,
  },
  sub: {
    margin: '0 0 14px', fontSize: 12, color: C.dim, lineHeight: 1.55,
    fontFamily: C.font,
  },
  input: {
    background: 'rgba(0,12,24,0.65)',
    border: `1px solid rgba(0,229,255,0.3)`,
    color: C.cyanHi,
    borderRadius: 0,
    padding: '9px 12px',
    fontSize: 13,
    outline: 'none',
    width: '100%',
    fontFamily: C.font,
    boxShadow: 'inset 0 0 12px rgba(0,229,255,0.08)',
  },
  select: {
    background: 'rgba(0,12,24,0.65)',
    border: `1px solid rgba(0,229,255,0.3)`,
    color: C.cyanHi,
    borderRadius: 0,
    padding: '9px 10px',
    fontSize: 13,
    fontFamily: C.font,
  },
  btn: {
    background: 'linear-gradient(135deg, rgba(0,229,255,0.16), rgba(0,110,255,0.12))',
    color: C.cyanHi,
    border: `1px solid ${C.cyan}`,
    borderRadius: 0,
    padding: '9px 18px',
    fontSize: 13,
    cursor: 'pointer',
    fontWeight: 700,
    whiteSpace: 'nowrap',
    fontFamily: C.font,
    textTransform: 'uppercase',
    letterSpacing: '1.2px',
    clipPath: notch(8),
    boxShadow: `0 0 12px rgba(0,229,255,0.3), inset 0 0 10px rgba(0,229,255,0.12)`,
  },
  ghost: {
    background: 'rgba(10,22,44,0.6)',
    color: '#9ad6e8',
    border: `1px solid ${C.lineDim}`,
    borderRadius: 0,
    padding: '9px 14px',
    fontSize: 12,
    cursor: 'pointer',
    whiteSpace: 'nowrap',
    fontFamily: C.font,
    textTransform: 'uppercase',
    letterSpacing: '1px',
  },
  button: {
    background: 'linear-gradient(135deg, rgba(0,229,255,0.16), rgba(0,110,255,0.12))',
    border: `1px solid ${C.cyan}`,
    color: C.cyanHi,
    borderRadius: 0,
    padding: '8px 14px',
    fontSize: 12, fontWeight: 700, cursor: 'pointer',
    fontFamily: C.font, textTransform: 'uppercase', letterSpacing: '1px',
    clipPath: notch(8),
    boxShadow: `0 0 10px rgba(0,229,255,0.28)`,
  },
  row: { display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', fontFamily: C.font },
  pill: {
    color: '#04121a', padding: '2px 10px', borderRadius: 2, fontSize: 11,
    fontWeight: 700, fontFamily: C.font, letterSpacing: '0.6px',
    textTransform: 'uppercase',
  },
  tag: {
    background: 'rgba(0,229,255,0.08)',
    color: '#8fd8e8',
    border: `1px solid ${C.lineDim}`,
    padding: '2px 8px',
    borderRadius: 2,
    fontSize: 11,
    marginRight: 4,
    fontFamily: C.font,
  },
  mono: {
    fontFamily: C.font, fontSize: 12, wordBreak: 'break-all', color: '#9fd8ea',
  },
  label: {
    fontSize: 11, color: C.dim, display: 'block', marginBottom: 4,
    textTransform: 'uppercase', letterSpacing: '0.14em', fontWeight: 700,
    fontFamily: C.font,
  },
  table: { width: '100%', borderCollapse: 'collapse', fontSize: 12, fontFamily: C.font },
  th: {
    background: 'rgba(0,229,255,0.07)',
    padding: '8px 10px', textAlign: 'left', color: C.cyan, fontWeight: 700,
    borderBottom: `1px solid ${C.line}`, whiteSpace: 'nowrap',
    textTransform: 'uppercase', letterSpacing: '0.1em', fontSize: 10,
  },
  td: {
    padding: '8px 10px', borderBottom: '1px solid rgba(0,229,255,0.09)',
    color: C.text, verticalAlign: 'top',
  },
  tr: { borderBottom: '1px solid rgba(0,229,255,0.09)' },
  pre: {
    fontFamily: C.font, fontSize: 11, color: '#7ee4c4', whiteSpace: 'pre-wrap',
    maxHeight: 320, overflowY: 'auto', background: 'rgba(0,6,14,0.8)',
    padding: 10, borderRadius: 0, margin: 0,
    border: `1px solid ${C.lineDim}`,
    boxShadow: 'inset 0 0 16px rgba(57,255,136,0.05)',
  },
  // stat blocks (SearchPanels / PlatformPanels)
  stats: {
    display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(104px, 1fr))',
    gap: 8, margin: '12px 0',
  },
  stat: {
    background: 'rgba(6,12,28,0.8)',
    border: `1px solid ${C.lineDim}`,
    borderRadius: 0,
    padding: '10px 12px',
    minWidth: 96,
    clipPath: notch(7),
    boxShadow: 'inset 0 0 12px rgba(0,229,255,0.06)',
  },
  num: { display: 'block', fontSize: 20, fontWeight: 700, color: C.cyan, textShadow: `0 0 10px rgba(0,229,255,0.6)` },
  statL: { fontSize: 10, color: C.dim, textTransform: 'uppercase', letterSpacing: '0.08em' },
  statLabel: { color: C.dim, fontSize: 11, marginTop: 2, textTransform: 'uppercase', letterSpacing: '0.08em' },
  phases: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(260px,1fr))', gap: 10 },
  phase: {
    background: 'rgba(6,12,28,0.8)', border: `1px solid ${C.lineDim}`,
    borderRadius: 0, padding: 12,
  },
  error: { color: C.red },
  ok: { color: C.green },
};

/* ---------- App.js shell styles (RESTful merge via makeStyles) ----------
 * keyof union of App.js's own keys; cybersecurity equivalents for all of them.
 */
export const appShell = (isMobile) => ({
  // page & chrome
  page: {
    background: 'radial-gradient(1200px 700px at 70% -10%, rgba(0,120,255,0.10), transparent 60%), radial-gradient(900px 600px at 10% 110%, rgba(255,43,214,0.08), transparent 60%), #04060e',
    minHeight: '100vh', color: C.text, fontFamily: C.font,
  },
  loading: { display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', color: C.cyan, fontSize: 16, textTransform: 'uppercase', letterSpacing: '0.2em' },
  header: {
    background: 'linear-gradient(180deg, rgba(8,14,30,0.98), rgba(4,7,16,0.98))',
    borderBottom: `1px solid ${C.line}`,
    boxShadow: `0 0 24px rgba(0,229,255,0.12)`,
    padding: isMobile ? '16px 14px' : '20px 32px',
    position: 'relative',
    overflow: 'hidden',
  },
  headerTitle: {
    margin: 0, fontSize: isMobile ? 24 : 38, fontWeight: 800, color: C.cyanHi,
    textTransform: 'uppercase', letterSpacing: '4px',
    textShadow: `0 0 18px rgba(0,229,255,0.8), 0 0 60px rgba(0,120,255,0.4)`,
    fontFamily: C.font,
  },
  headerSub: { margin: '4px 0 0', color: C.dim, fontSize: 12, letterSpacing: '0.16em', textTransform: 'uppercase' },
  keyBtn: {
    background: 'rgba(10,22,44,0.6)', border: `1px solid ${C.lineDim}`, color: '#9ad6e8',
    borderRadius: 0, padding: '8px 16px', fontSize: 12, cursor: 'pointer',
    display: 'flex', alignItems: 'center', gap: 8, fontFamily: C.font,
    textTransform: 'uppercase', letterSpacing: '1px',
  },
  keyBadge: { background: C.green, color: '#04121a', borderRadius: 2, padding: '1px 8px', fontSize: 10, fontWeight: 700 },
  keyBtnPos: isMobile ? { position: 'static', margin: '12px auto 0' } : { position: 'absolute', top: 22, right: 28 },
  statsBar: {
    display: 'flex', gap: 0, marginTop: 16,
    background: 'rgba(6,12,28,0.85)', border: `1px solid ${C.lineDim}`,
    overflow: 'hidden', flexWrap: 'wrap', clipPath: notch(10),
  },
  statItem: {
    padding: isMobile ? '8px 10px' : '10px 18px', display: 'flex',
    flexDirection: 'column', alignItems: 'center', flex: 1, minWidth: 80,
  },
  statNum: { fontSize: 20, fontWeight: 700, color: C.cyan, textShadow: `0 0 10px rgba(0,229,255,0.6)` },
  statDivider: { width: 1, background: C.lineDim, alignSelf: 'stretch' },
  content: { padding: isMobile ? '16px 14px' : '20px 32px' },

  // tool grid
  toolGrid: { display: 'grid', gridTemplateColumns: isMobile ? '1fr' : 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16, marginBottom: 20 },
  toolCard: {
    background: `linear-gradient(165deg, rgba(10,18,40,0.92), rgba(5,9,20,0.96))`,
    border: `1px solid ${C.lineDim}`,
    borderTop: `2px solid ${C.cyan}`,
    borderRadius: 0, padding: 20,
    clipPath: notch(10),
    boxShadow: '0 0 14px rgba(0,229,255,0.08)',
  },
  toolHeader: { display: 'flex', gap: 12, alignItems: 'flex-start', marginBottom: 12 },
  toolIcon: {
    display: 'flex', alignItems: 'center', justifyContent: 'center', width: 36, height: 36,
    borderRadius: 0, color: C.cyanHi, fontWeight: 700, fontSize: 14, flexShrink: 0,
    border: `1px solid ${C.line}`, boxShadow: `0 0 10px rgba(0,229,255,0.25)`,
  },
  toolName: { fontSize: 14, fontWeight: 700, color: C.cyanHi, textTransform: 'uppercase', letterSpacing: '1.2px' },
  toolDesc: { fontSize: 12, color: C.dim, marginTop: 2, lineHeight: 1.4 },
  toolSources: { display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 12 },
  sourcePill: {
    background: 'rgba(0,229,255,0.08)', color: '#8fd8e8', padding: '2px 8px',
    borderRadius: 2, fontSize: 10, border: `1px solid ${C.lineDim}`, fontFamily: C.font,
  },

  // live result cards
  liveGrid: { display: 'grid', gridTemplateColumns: isMobile ? '1fr' : 'repeat(auto-fit, minmax(320px, 1fr))', gap: 10, marginBottom: 10 },
  liveCard: {
    background: 'rgba(7,11,24,0.85)', border: `1px solid ${C.lineDim}`,
    borderRadius: 0, padding: '13px 15px',
    boxShadow: 'inset 0 0 14px rgba(0,229,255,0.05)',
  },
  lcHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 },
  lcTitle: { fontSize: 13, fontWeight: 700, color: C.cyan, textTransform: 'uppercase', letterSpacing: '0.08em' },
  lcGrid: { display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr', gap: '4px 16px', fontSize: 12 },
  lcLabel: { color: C.dim },
  resultRow: {
    display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', padding: '8px 12px',
    background: 'rgba(7,11,24,0.85)', border: `1px solid ${C.lineDim}`, borderRadius: 0, marginBottom: 6,
  },

  // charts
  chartsRow: { display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr 1.2fr', gap: 16, marginBottom: 20 },
  chartBox: {
    background: `linear-gradient(165deg, rgba(10,18,40,0.92), rgba(5,9,20,0.96))`,
    border: `1px solid ${C.lineDim}`, borderRadius: 0, padding: '14px 16px',
    clipPath: notch(10),
  },
  chartLabel: { fontSize: 12, color: C.cyan, fontWeight: 700, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.1em' },

  // buttons / extras
  smallBtn: {
    background: 'rgba(10,22,44,0.6)', border: `1px solid ${C.lineDim}`, color: '#9ad6e8',
    borderRadius: 0, padding: '6px 12px', fontSize: 12, cursor: 'pointer',
    whiteSpace: 'nowrap', fontFamily: C.font, textTransform: 'uppercase', letterSpacing: '1px',
  },
  protectBtn: {
    background: 'rgba(255,59,92,0.14)', color: C.red, border: `1px solid ${C.red}`,
    borderRadius: 0, padding: '5px 14px', fontSize: 12, cursor: 'pointer',
    fontWeight: 700, whiteSpace: 'nowrap', fontFamily: C.font,
    textTransform: 'uppercase', letterSpacing: '1px',
    boxShadow: `0 0 10px rgba(255,59,92,0.25)`,
  },
  typeBadge: { background: 'rgba(0,229,255,0.12)', color: C.cyan, padding: '2px 8px', borderRadius: 2, fontSize: 11, fontFamily: C.font },

  // modals
  overlay: {
    position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
    background: 'rgba(2,4,10,0.82)', backdropFilter: 'blur(3px)', zIndex: 50,
    display: 'flex', alignItems: 'center', justifyContent: 'center',
  },
  modal: {
    background: `linear-gradient(165deg, rgba(10,18,40,0.98), rgba(4,8,18,0.98))`,
    border: `1px solid ${C.line}`, clipPath: notch(12),
    boxShadow: `0 0 30px rgba(0,229,255,0.25)`,
    borderRadius: 0, width: 'min(720px, 92vw)', maxHeight: '84vh',
    overflowY: 'auto', padding: 22, position: 'relative',
  },
  closeBtn: {
    background: 'transparent', border: `1px solid ${C.lineDim}`, color: C.red,
    borderRadius: 0, cursor: 'pointer', fontFamily: C.font, padding: '4px 10px',
    position: 'absolute', top: 12, right: 14, fontSize: 12,
  },
  keyRow: { marginBottom: 10 },
});
