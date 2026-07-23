const api = {
  headers: (extra = {}) => {
    const h = { ...extra };
    try {
      const local = (localStorage.getItem('randallLocalToken') || '').trim();
      if (local) {
        h['X-Randall-Token'] = local;
        h['Authorization'] = `Bearer ${local}`;
      }
      const agentTok = (localStorage.getItem('randallLabsAgentToken') || '').trim();
      if (agentTok) h['X-Randall-Agent-Token'] = agentTok;
    } catch { /* ignore */ }
    return h;
  },
  get: async (path) => {
    const r = await fetch(path, { headers: api.headers() });
    const data = await r.json().catch(() => null);
    if (!r.ok) throw new Error(data?.error || data?.message || `${r.status} ${path}`);
    return data;
  },
  post: (path, body) => fetch(path, {
    method: 'POST',
    headers: api.headers({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
  }).then(async (r) => {
    const data = r.status === 204 ? null : await r.json().catch(() => null);
    if (!r.ok) throw new Error(data?.error || data?.message || `${r.status} ${path}`);
    return data;
  }),
  put: (path, body) => fetch(path, {
    method: 'PUT',
    headers: api.headers({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
  }).then(async (r) => {
    const data = r.status === 204 ? null : await r.json().catch(() => null);
    if (!r.ok) throw new Error(data?.error || data?.message || `${r.status} ${path}`);
    return data;
  }),
  del: async (path) => {
    const r = await fetch(path, { method: 'DELETE', headers: api.headers() });
    const data = r.status === 204 ? null : await r.json().catch(() => null);
    if (!r.ok) throw new Error(data?.error || data?.message || `${r.status} ${path}`);
    return data;
  },
};

const HIDDEN_TARGETS = new Set(['cfpass']);

function isVisibleTarget(t) {
  const name = (t.name || '').toLowerCase();
  const path = (t.configPath || '').toLowerCase();
  if (HIDDEN_TARGETS.has(name)) return false;
  if (name.includes('cfpass') || path.includes('cfpass')) return false;
  return true;
}

const logEl = document.getElementById('fuzz-log');
const statusEl = document.getElementById('fuzz-status');
const startBtn = document.getElementById('fuzz-start');
const stopBtn = document.getElementById('fuzz-stop');

/** Soft cap for in-memory live log (survives leaving the Fuzz view). */
const LOG_BUFFER_MAX = 2000;
/** @type {{ line: string, cls: string, at: string|null }[]} */
let logBuffer = [];
/** Dedup keys for server replay + SignalR overlap after reconnect. */
const seenLogKeys = new Set();

function logEntryKey(at, kind, message) {
  return `${at || ''}|${kind || ''}|${message || ''}`;
}

function formatLogTs(isoOrDate) {
  try {
    const d = isoOrDate ? new Date(isoOrDate) : new Date();
    if (Number.isNaN(d.getTime())) return formatLogTs();
    const p = (n, w = 2) => String(n).padStart(w, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())},${p(d.getMilliseconds(), 3)}`;
  } catch {
    return '----/--/-- --:--:--,---';
  }
}

function paintLogLine(entry) {
  if (!logEl) return;
  const row = document.createElement('div');
  row.className = entry.cls ? `log-line log-${entry.cls}` : 'log-line log-info';
  const ts = document.createElement('span');
  ts.className = 'log-ts';
  ts.textContent = `[${formatLogTs(entry.at)}]`;
  const msg = document.createElement('span');
  msg.className = 'log-msg';
  msg.textContent = ` ${entry.line}`;
  row.appendChild(ts);
  row.appendChild(msg);
  logEl.appendChild(row);
}

/** Replay buffered lines into the Live log panel (e.g. after returning to Fuzz). */
function rehydrateFuzzLog() {
  if (!logEl) return;
  logEl.innerHTML = '';
  for (const entry of logBuffer) paintLogLine(entry);
  logEl.scrollTop = logEl.scrollHeight;
}

function clearFuzzLog() {
  logBuffer = [];
  seenLogKeys.clear();
  if (logEl) logEl.innerHTML = '';
}

function appendLogUnique(message, cls = '', at = null) {
  const key = logEntryKey(at, cls, message);
  if (seenLogKeys.has(key)) return;
  seenLogKeys.add(key);
  appendLog(message, cls, at);
}

function mergeServerLogs(entries) {
  if (!Array.isArray(entries) || entries.length === 0) return;
  for (const e of entries) {
    appendLogUnique(e.message || '', (e.kind || 'info').toLowerCase(), e.at);
  }
  if (document.getElementById('view-fuzz')?.classList.contains('visible'))
    rehydrateFuzzLog();
}

function appendLog(line, cls = '', at = null) {
  const entry = { line: line || '', cls: cls || '', at: at || new Date().toISOString() };
  logBuffer.push(entry);
  while (logBuffer.length > LOG_BUFFER_MAX) logBuffer.shift();

  if (!logEl) return;
  // Keep appending while the view is hidden so an active run never loses lines.
  paintLogLine(entry);
  while (logEl.childElementCount > LOG_BUFFER_MAX)
    logEl.removeChild(logEl.firstChild);
  logEl.scrollTop = logEl.scrollHeight;
}

function setStatus(text) {
  statusEl.textContent = text;
}

function isFuzzSessionActive(s) {
  if (!s) return false;
  if (s.running) return true;
  const phase = (s.phase || '').toLowerCase();
  return phase === 'starting' || phase === 'running' || phase === 'stopping';
}

function applyFuzzSessionStatus(s) {
  if (!s) return;
  const active = isFuzzSessionActive(s);
  startBtn.disabled = active;
  stopBtn.disabled = !active;

  if (s.configPath) {
    const sel = document.getElementById('fuzz-target');
    if (sel && [...sel.options].some((o) => o.value === s.configPath))
      sel.value = s.configPath;
  }

  if (active) {
    const iter = Number(s.iterations) > 0 ? `iter ${s.iterations} · ` : '';
    setStatus(`${iter}${s.phase}: ${s.lastMessage || '…'}`);
    return;
  }

  const phase = (s.phase || 'idle').toLowerCase();
  if (phase === 'idle') {
    setStatus('Idle');
    startBtn.disabled = false;
    stopBtn.disabled = true;
    return;
  }

  setStatus(`${s.phase}: ${s.lastMessage || ''}`);
  startBtn.disabled = false;
  stopBtn.disabled = true;
}

async function syncFuzzSession({ fetchLogs = true } = {}) {
  const s = await api.get('/api/fuzz/status');
  applyFuzzSessionStatus(s);
  if (fetchLogs) {
    try {
      const data = await api.get('/api/fuzz/logs');
      mergeServerLogs(data.logs);
    } catch { /* older server or logs not ready yet */ }
  }
  return s;
}

function switchView(name) {
  document.querySelectorAll('.nav-btn').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('visible', v.id === `view-${name}`));
  if (name === 'fuzz') rehydrateFuzzLog();
  if (name === 'dashboard') loadDashboard().catch(() => {});
  if (name === 'stalking') loadStalkingView().catch(() => {});
  if (name === 'proxy') loadProxy().catch(() => {});
  if (name === 'campaign') loadCampaignView().catch(() => {});
  if (name === 'models') loadModels().catch(() => {});
  if (name === 'graph') loadGraphView().catch(() => {});
  if (name === 'bundles') loadBundlesView().catch(() => {});
  if (name === 'help') loadHelpView().catch(() => {});
  if (name === 'crashes') loadCrashes(document.getElementById('crash-filter')?.value || '').catch(() => {});
}

/* —— Help (served markdown from docs/) —— */
let helpLoaded = false;

function parseHelpRef(ref) {
  const raw = String(ref || '').trim();
  const hashIdx = raw.indexOf('#');
  if (hashIdx < 0) return { path: raw, hash: '' };
  return { path: raw.slice(0, hashIdx), hash: raw.slice(hashIdx + 1) };
}

function slugifyHeading(text) {
  return String(text || '')
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-');
}

function ensureHelpHeadingIds(root) {
  root.querySelectorAll('h1, h2, h3, h4').forEach((h) => {
    if (!h.id) h.id = slugifyHeading(h.textContent);
  });
}

function scrollHelpToHash(hash) {
  if (!hash) return;
  const body = document.getElementById('help-content');
  const el = body?.querySelector(`#${CSS.escape(hash)}`) || document.getElementById(hash);
  el?.scrollIntoView({ block: 'start', behavior: 'smooth' });
}

async function loadHelpView(openPath) {
  const indexEl = document.getElementById('help-index');
  if (!indexEl) return;
  if (!helpLoaded) {
    const entries = await api.get('/api/docs');
    const groups = {};
    for (const e of entries) {
      (groups[e.group] ||= []).push(e);
    }
    indexEl.innerHTML = Object.entries(groups).map(([group, items]) =>
      `<div class="help-group"><h3>${escapeAttr(group)}</h3>${
        items.map((i) =>
          `<button type="button" class="help-link" data-doc="${escapeAttr(i.path)}">${escapeAttr(i.title)}</button>`
        ).join('')
      }</div>`).join('');
    indexEl.querySelectorAll('[data-doc]').forEach((btn) => {
      btn.addEventListener('click', () => openHelpDoc(btn.dataset.doc).catch((err) => {
        document.getElementById('help-content').textContent = err.message;
      }));
    });
    helpLoaded = true;
  }
  if (openPath) await openHelpDoc(openPath);
}

async function openHelpDoc(pathOrRef) {
  const { path, hash } = parseHelpRef(pathOrRef);
  if (!path) return;
  const doc = await api.get(`/api/docs/${path.split('/').map(encodeURIComponent).join('/')}`);
  document.getElementById('help-title').textContent = doc.title;
  const body = document.getElementById('help-content');
  const md = typeof marked !== 'undefined' ? marked.parse(doc.markdown || '') : `<pre>${escapeAttr(doc.markdown || '')}</pre>`;
  body.innerHTML = md;
  ensureHelpHeadingIds(body);
  // Stable anchor used by Campaign → RE companions "Open in Help"
  const apiFridaH = [...body.querySelectorAll('h2, h3')].find((h) =>
    /api\s*monitor/i.test(h.textContent || '') && /frida/i.test(h.textContent || ''));
  if (apiFridaH) apiFridaH.id = 'api-monitor-frida';
  body.querySelectorAll('a[href]').forEach((a) => {
    const href = a.getAttribute('href') || '';
    if (href.includes('.md') && !href.startsWith('http')) {
      a.addEventListener('click', (ev) => {
        ev.preventDefault();
        openHelpDoc(href.replace(/^\.\//, '')).catch(() => {});
      });
    } else if (href.startsWith('http')) {
      a.target = '_blank';
      a.rel = 'noopener';
    } else if (href.startsWith('#')) {
      a.addEventListener('click', (ev) => {
        ev.preventDefault();
        scrollHelpToHash(href.slice(1));
      });
    }
  });
  document.querySelectorAll('.help-link').forEach((b) =>
    b.classList.toggle('active', b.dataset.doc === path));
  if (hash) {
    requestAnimationFrame(() => scrollHelpToHash(hash));
  }
}

document.querySelectorAll('[data-help]').forEach((btn) => {
  btn.addEventListener('click', () => {
    switchView('help');
    loadHelpView(btn.dataset.help).catch(() => {});
  });
});


document.querySelectorAll('.nav-btn').forEach((btn) => {
  btn.addEventListener('click', () => switchView(btn.dataset.view));
});

function setNavCollapsed(collapsed) {
  document.body.classList.toggle('nav-collapsed', collapsed);
  localStorage.setItem('randfuzz.navCollapsed', collapsed ? '1' : '0');
  const toggle = document.getElementById('nav-toggle');
  if (toggle) {
    toggle.textContent = collapsed ? '⟩' : '⟨';
    toggle.title = collapsed ? 'Show navigation' : 'Hide navigation';
    toggle.setAttribute('aria-label', toggle.title);
  }
}

function initNavToggle() {
  setNavCollapsed(localStorage.getItem('randfuzz.navCollapsed') === '1');
  document.getElementById('nav-toggle')?.addEventListener('click', () => {
    setNavCollapsed(!document.body.classList.contains('nav-collapsed'));
  });
  document.getElementById('nav-reopen')?.addEventListener('click', () => setNavCollapsed(false));
}

function themeLabel(name) {
  if (name === 'light') return 'Light';
  if (name === 'cyber') return 'Cyber';
  return 'Dark';
}

function setThemeDefaultLabel(theme, { saving = false } = {}) {
  const el = document.getElementById('theme-default-label');
  if (!el) return;
  el.textContent = saving
    ? `Saving ${themeLabel(theme)}…`
    : `Skin: ${themeLabel(theme)} (saved for next open)`;
}

/** Apply skin immediately in the UI. */
function applyTheme(name) {
  const theme = ['dark', 'light', 'cyber'].includes(name) ? name : 'light';
  document.documentElement.setAttribute('data-theme', theme);
  document.querySelectorAll('.theme-btn').forEach((b) => {
    b.classList.toggle('active', b.dataset.theme === theme);
  });
  return theme;
}

/** User picked a skin: switch now and persist (browser + server). */
async function selectTheme(name) {
  const theme = applyTheme(name);
  setThemeDefaultLabel(theme, { saving: true });
  try { localStorage.setItem('randfuzz.theme', theme); } catch { /* ignore */ }
  try {
    await api.put('/api/ui/prefs', { theme });
  } catch {
    /* localStorage still restores this browser on reopen */
  }
  setThemeDefaultLabel(theme);
  return theme;
}

async function initThemePicker() {
  let local = null;
  try { local = localStorage.getItem('randfuzz.theme'); } catch { /* ignore */ }

  let theme = ['dark', 'light', 'cyber'].includes(local) ? local : null;
  if (!theme) {
    try {
      const prefs = await api.get('/api/ui/prefs');
      if (prefs?.theme && ['dark', 'light', 'cyber'].includes(prefs.theme))
        theme = prefs.theme;
    } catch { /* ignore */ }
  }

  // No saved choice → Light. Do not write prefs until the user picks a skin.
  theme = theme || 'light';
  applyTheme(theme);
  setThemeDefaultLabel(theme);

  document.querySelectorAll('.theme-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      selectTheme(btn.dataset.theme).catch(() => {});
    });
  });
}

// —— Fuzzing platform selector (Windows vs Linux) ——
// Filters the Fuzz view (and doctor) to the OS the user is fuzzing. "auto" tracks the host OS
// reported by /api/platform; explicit windows/linux lets the user preview the other platform.
const platformState = { host: 'linux', selected: 'auto', resolved: 'linux' };

function platformLabel(p) {
  if (p === 'windows') return 'Windows';
  if (p === 'linux') return 'Linux';
  if (p === 'auto') return 'Auto';
  return p || '—';
}

function resolvePlatform(selected, host) {
  return selected === 'windows' || selected === 'linux' ? selected : host;
}

function setPlatformLabel() {
  const el = document.getElementById('platform-label');
  if (el) {
    const sel = platformState.selected;
    const selName = sel === 'auto'
      ? `Auto → ${platformLabel(platformState.resolved)}`
      : platformLabel(sel);
    el.textContent = `Platform: ${selName} · host ${platformLabel(platformState.host)}`;
  }
  const badge = document.getElementById('platform-badge');
  if (badge) {
    const ico = platformState.resolved === 'windows' ? '⊞' : '🐧';
    badge.textContent = `${ico} ${platformLabel(platformState.resolved)}`;
    badge.classList.toggle('platform-badge-win', platformState.resolved === 'windows');
    badge.classList.toggle('platform-badge-linux', platformState.resolved === 'linux');
  }
}

/** Show only controls tagged for the resolved platform; cross-platform controls are untagged. */
function applyPlatformVisibility() {
  const resolved = platformState.resolved;
  document.querySelectorAll('[data-platform-scope]').forEach((el) => {
    const scope = el.dataset.platformScope;
    const show = scope === 'cross' || scope === resolved;
    el.classList.toggle('platform-hidden', !show);
  });
  document.querySelectorAll('.platform-btn').forEach((b) => {
    b.classList.toggle('active', b.dataset.platform === platformState.selected);
  });
  if (resolved === 'linux') {
    renderLinuxToolStatus().catch(() => {});
    renderCheckSec().catch(() => {});
  }
}

/** Live green/red probe of the Linux toolchain via the doctor, rendered as chips. */
async function renderLinuxToolStatus() {
  const grid = document.getElementById('fuzz-linux-tools');
  const badge = document.getElementById('fuzz-linux-ready');
  if (!grid || platformState.resolved !== 'linux') return;

  const targetSel = document.getElementById('fuzz-target');
  const configPath = targetSel && targetSel.value;
  if (!configPath) {
    grid.innerHTML = '<span class="hint">Pick a target profile to probe tools…</span>';
    if (badge) badge.textContent = '';
    return;
  }

  grid.innerHTML = '<span class="hint">Probing toolchain…</span>';
  try {
    const report = await api.get(
      `/api/doctor?configPath=${encodeURIComponent(configPath)}&platform=linux`);
    const linux = (report.checks || []).filter((c) => c.id.indexOf('linux:') === 0);
    let ok = 0;
    grid.innerHTML = linux.map((c) => {
      const good = c.status === 'ok';
      if (good) ok += 1;
      const optional = /optional/i.test(c.message);
      const name = c.id.replace(/^linux:/, '');
      const cls = good ? 'tool-ok' : (optional ? 'tool-opt' : 'tool-miss');
      const icon = good ? '✓' : (optional ? '○' : '✗');
      return `<span class="tool-chip ${cls}" role="button" tabindex="0" data-msg="${escapeAttr(c.message)}"><b>${icon}</b> ${escapeAttr(name)}</span>`;
    }).join('');
    if (badge) badge.textContent = linux.length ? `(${ok}/${linux.length} ready)` : '';

    // Click a chip → show its full doctor message / install hint.
    const detail = document.getElementById('fuzz-linux-tool-detail');
    grid.querySelectorAll('.tool-chip').forEach((chip) => {
      const show = () => {
        if (!detail) return;
        detail.textContent = chip.dataset.msg || '';
        detail.classList.remove('hidden');
      };
      chip.addEventListener('click', show);
      chip.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); show(); } });
    });
  } catch (err) {
    grid.innerHTML = `<span class="hint">Could not probe toolchain: ${escapeAttr(err.message)}</span>`;
  }
}

/** Inline checksec — exploit mitigations of the selected target's binary. */
async function renderCheckSec() {
  const grid = document.getElementById('fuzz-checksec');
  if (!grid || platformState.resolved !== 'linux') return;
  const targetSel = document.getElementById('fuzz-target');
  const configPath = targetSel && targetSel.value;
  if (!configPath) return;

  grid.innerHTML = '<span class="hint">Inspecting…</span>';
  try {
    const r = await api.get(`/api/checksec?configPath=${encodeURIComponent(configPath)}`);
    if (!r.hasExecutable) {
      grid.innerHTML = '<span class="hint">No local binary for this target (remote/managed) — build it to inspect.</span>';
      return;
    }
    const chip = (label, on, good = on) =>
      `<span class="tool-chip ${good ? 'tool-ok' : 'tool-miss'}"><b>${good ? '✓' : '✗'}</b> ${label}</span>`;
    const relroGood = r.relro === 'full';
    grid.innerHTML =
      `<span class="tool-chip ${'tool-opt'}">tier: ${escapeAttr(r.tier)}</span>` +
      chip('NX', r.nx) +
      chip('Canary', r.canary) +
      chip('PIE', r.pie) +
      `<span class="tool-chip ${relroGood ? 'tool-ok' : 'tool-miss'}"><b>${relroGood ? '✓' : '✗'}</b> RELRO:${escapeAttr(r.relro)}</span>` +
      chip('FORTIFY', r.fortify) +
      `<span class="tool-chip tool-opt" title="system ASLR">ASLR: ${escapeAttr(r.aslr)}</span>`;
  } catch (err) {
    grid.innerHTML = `<span class="hint">checksec unavailable: ${escapeAttr(err.message)}</span>`;
  }
}

/** User picked a platform: apply now and persist (browser + server). */
async function selectPlatform(name) {
  const sel = ['auto', 'windows', 'linux'].includes(name) ? name : 'auto';
  platformState.selected = sel;
  platformState.resolved = resolvePlatform(sel, platformState.host);
  try { localStorage.setItem('randfuzz.platform', sel); } catch { /* ignore */ }
  setPlatformLabel();
  applyPlatformVisibility();
  try { await api.put('/api/ui/prefs', { platform: sel }); } catch { /* localStorage still restores */ }
  return sel;
}

async function initPlatformPicker() {
  try {
    const info = await api.get('/api/platform');
    if (info?.host) platformState.host = info.host;
  } catch { /* default host stays linux */ }

  let local = null;
  try { local = localStorage.getItem('randfuzz.platform'); } catch { /* ignore */ }
  let sel = ['auto', 'windows', 'linux'].includes(local) ? local : null;
  if (!sel) {
    try {
      const prefs = await api.get('/api/ui/prefs');
      if (['auto', 'windows', 'linux'].includes(prefs?.platform)) sel = prefs.platform;
    } catch { /* ignore */ }
  }

  platformState.selected = sel || 'auto';
  platformState.resolved = resolvePlatform(platformState.selected, platformState.host);
  setPlatformLabel();
  applyPlatformVisibility();

  document.querySelectorAll('.platform-btn').forEach((btn) => {
    btn.addEventListener('click', () => { selectPlatform(btn.dataset.platform).catch(() => {}); });
  });

  document.getElementById('fuzz-linux-refresh')?.addEventListener('click', () => {
    renderLinuxToolStatus().catch(() => {});
    renderCheckSec().catch(() => {});
  });
  // Re-probe when the target changes while Linux is active.
  document.getElementById('fuzz-target')?.addEventListener('change', () => {
    if (platformState.resolved === 'linux') {
      renderLinuxToolStatus().catch(() => {});
      renderCheckSec().catch(() => {});
    }
  });
}

async function loadHealth() {
  const h = await api.get('/api/health');
  const auth = h.authRequired ? ' · token required' : '';
  document.getElementById('health-label').textContent = `${h.name} ${h.version} · ${h.status}${auth}`;
  if (h.authRequired) {
    try {
      let local = (localStorage.getItem('randallLocalToken') || '').trim();
      if (!local) {
        local = (window.prompt('This Randfuzz host requires RANDALL_AGENT_TOKEN. Paste the token:', '') || '').trim();
        if (local) localStorage.setItem('randallLocalToken', local);
      }
    } catch { /* ignore */ }
  }
}

let updateBannerState = null;

function isSafeNotesUrl(url) {
  try {
    const u = new URL(String(url || ''));
    return u.protocol === 'https:' && (u.hostname === 'github.com' || u.hostname === 'www.github.com');
  } catch {
    return false;
  }
}

function renderUpdateBanner(st) {
  const ban = document.getElementById('update-banner');
  const text = document.getElementById('update-banner-text');
  const notes = document.getElementById('update-banner-notes');
  const applyBtn = document.getElementById('update-banner-apply');
  if (!ban || !text) return;
  updateBannerState = st;
  const show = st && st.updateAvailable && st.majorUpdate && !st.bannerSuppressed && st.signatureValid;
  ban.classList.toggle('hidden', !show);
  if (!show) return;
  text.textContent = st.message
    || `Major update available: ${st.currentVersion} → ${st.lastCheckedVersion}`;
  if (notes) {
    if (st.notesUrl && isSafeNotesUrl(st.notesUrl)) {
      notes.href = st.notesUrl;
      notes.classList.remove('hidden');
    } else {
      notes.removeAttribute('href');
      notes.classList.add('hidden');
    }
  }
  if (applyBtn) applyBtn.disabled = false;
}

async function refreshUpdateBanner(doCheck) {
  try {
    const st = doCheck
      ? await api.post('/api/update/check?force=1', {})
      : await api.get('/api/update/status');
    const normalized = st.currentVersion != null && st.bannerSuppressed !== undefined
      ? st
      : {
          currentVersion: st.currentVersion,
          lastCheckedVersion: st.latestVersion,
          updateAvailable: st.updateAvailable,
          majorUpdate: st.majorUpdate,
          signatureValid: st.signatureValid,
          notesUrl: st.notesUrl,
          bannerSuppressed: !(st.updateAvailable && st.majorUpdate && st.signatureValid),
          message: st.message,
        };
    if (doCheck) {
      const status = await api.get('/api/update/status');
      renderUpdateBanner(status);
      return status;
    }
    renderUpdateBanner(normalized);
    return normalized;
  } catch (err) {
    console.warn('update check', err);
    return null;
  }
}

document.getElementById('update-banner-check')?.addEventListener('click', () => {
  refreshUpdateBanner(true).catch(() => {});
});
document.getElementById('update-banner-dismiss')?.addEventListener('click', async () => {
  try {
    const st = await api.post('/api/update/dismiss', {
      version: updateBannerState?.lastCheckedVersion || null,
    });
    renderUpdateBanner(st);
  } catch (err) {
    console.warn(err);
  }
});
document.getElementById('update-banner-apply')?.addEventListener('click', async () => {
  const applyBtn = document.getElementById('update-banner-apply');
  const text = document.getElementById('update-banner-text');
  if (!window.confirm('Apply the verified update now? Stop active fuzz sessions first. This downloads a signed release and replaces binaries.'))
    return;
  if (applyBtn) applyBtn.disabled = true;
  if (text) text.textContent = 'Applying verified update…';
  try {
    const r = await api.post('/api/update/apply?confirm=true', { confirm: true });
    if (text) text.textContent = r.message || 'Update applied — restart Randfuzz.';
    if (r.restartRequired)
      window.alert((r.message || 'Update applied.') + '\n\nRestart the UI/server to finish.');
  } catch (err) {
    if (text) text.textContent = err.message || 'Update failed';
    if (applyBtn) applyBtn.disabled = false;
  }
});

// —— Recipe catalog (Scare Floor): browse target-class recipes and instantiate projects ——
let recipeCatalogInit = false;

async function loadRecipeCatalog() {
  const listEl = document.getElementById('recipe-catalog-list');
  if (!listEl) return;
  try {
    const catSel = document.getElementById('recipe-catalog-category');
    const search = document.getElementById('recipe-catalog-search')?.value || '';
    const category = catSel?.value || 'all';
    const data = await api.get(
      `/api/case/catalog?category=${encodeURIComponent(category)}&search=${encodeURIComponent(search)}`);

    const countEl = document.getElementById('recipe-catalog-count');
    if (countEl) countEl.textContent = `(${data.entries.length}/${data.count})`;

    // Populate categories once.
    if (!recipeCatalogInit && catSel && Array.isArray(data.categories)) {
      for (const c of data.categories) {
        const o = document.createElement('option');
        o.value = c; o.textContent = c;
        catSel.appendChild(o);
      }
      recipeCatalogInit = true;
    }

    if (!data.entries.length) {
      listEl.innerHTML = '<span class="hint">No recipes match.</span>';
      return;
    }
    listEl.innerHTML = data.entries.map((e) => `
      <div class="recipe-card">
        <div class="recipe-card-main">
          <strong>${escapeAttr(e.name)}</strong>
          <span class="recipe-kind">${escapeAttr(e.kind)}</span>
          <span class="recipe-cat">${escapeAttr(e.category)}</span>
          <div class="recipe-tags">${(e.tags || []).map((t) => `<span class="recipe-tag">${escapeAttr(t)}</span>`).join('')}</div>
        </div>
        <button type="button" class="btn primary recipe-make" data-id="${escapeAttr(e.id)}" data-name="${escapeAttr(e.id)}">Create project</button>
      </div>`).join('');

    listEl.querySelectorAll('.recipe-make').forEach((btn) => {
      btn.addEventListener('click', () => instantiateRecipe(btn.dataset.id));
    });
  } catch (err) {
    listEl.innerHTML = `<span class="hint">Catalog error: ${escapeAttr(err.message)}</span>`;
  }
}

async function instantiateRecipe(id) {
  try {
    const r = await api.post('/api/case/catalog/instantiate', { id, localFolder: true });
    setStatus(r.message || `Created project from ${id}`);
    await loadTargets();                 // refresh Target dropdowns with the new project
    const caseSel = document.getElementById('case-project');
    if (caseSel) {
      // select the newly created project (id is the default name)
      for (const opt of caseSel.options) {
        if (opt.value.includes(`${id}.yaml`) || opt.textContent.startsWith(id)) { caseSel.value = opt.value; break; }
      }
      refreshCaseProject?.();
    }
  } catch (err) {
    setStatus(`Recipe create failed: ${err.message}`);
  }
}

function initRecipeCatalog() {
  document.getElementById('recipe-catalog-category')?.addEventListener('change', () => loadRecipeCatalog());
  let t = null;
  document.getElementById('recipe-catalog-search')?.addEventListener('input', () => {
    clearTimeout(t); t = setTimeout(() => loadRecipeCatalog(), 250);
  });
}

let stalkProject = null;
/** Server/history timeline from last /api/stalk payload (persists across live ticks). */
let stalkServerTimeline = [];
let stalkLiveTimeline = [];
let stalkPollTick = 0;
/** When false, live SignalR/poll must not overwrite stalker widgets — timeline selection is pinned. */
let stalkFollowLive = true;
/** @type {null | { key: string, iteration: number, kind: string, label: string, crashId: string|null, index: number }} */
let stalkSelection = null;
/** Last painted timeline points (for re-highlight / click resolve). */
let stalkRenderedTimeline = [];
/** iteration → crash Guid (filled from server timeline / crash list). */
const stalkCrashIdByIteration = new Map();
/** Monotonic token so stale loadDashboard responses cannot clobber a newer pin/live fetch. */
let stalkLoadSeq = 0;
let stalkTimelineClickBound = false;

async function loadTargets() {
  const targets = (await api.get('/api/targets')).filter(isVisibleTarget);
  const sel = document.getElementById('fuzz-target');
  const filter = document.getElementById('crash-filter');
  const caseSel = document.getElementById('case-project');
  sel.innerHTML = targets.map((t) =>
    `<option value="${t.configPath}" data-name="${t.name}">${t.name} [${t.kind}] — ${t.description || ''}</option>`).join('');
  filter.innerHTML = '<option value="">All</option>' +
    targets.map((t) => `<option value="${t.name}">${t.name}</option>`).join('');
  if (caseSel) {
    caseSel.innerHTML = targets.map((t) => `<option value="${t.name}">${t.name} [${t.kind}]</option>`).join('');
  }
  await refreshFuzzTargetTip();
  return targets;
}

async function refreshFuzzTargetTip() {
  const tip = document.getElementById('fuzz-target-tip');
  const sel = document.getElementById('fuzz-target');
  if (!tip || !sel?.selectedOptions?.length) return;
  const name = sel.selectedOptions[0].dataset.name;
  if (!name) return;
  try {
    const p = await api.get(`/api/case/project/${encodeURIComponent(name)}`);
    tip.textContent = p.hasLocalExecutable
      ? `Local: ${p.executable?.split(/[/\\]/).pop()} · mutators: ${(p.mutators || []).join(', ') || 'default'}`
      : `Remote ${p.kind.toUpperCase()} → ${p.host}:${p.port} (no local exe) · ${p.tip}`;
  } catch {
    tip.textContent = 'Pick a profile — remote TCP/UDP needs only host:port in the YAML.';
  }
}

document.getElementById('fuzz-target')?.addEventListener('change', () => {
  refreshFuzzTargetTip().catch(() => {});
});

function statusClass(status) {
  const s = (status || '').toLowerCase();
  if (s.includes('crash') || s.includes('inspect')) return 'status-crash';
  if (s.includes('trac')) return 'status-tracing';
  if (s.includes('attach')) return 'status-attached';
  return 'status-idle';
}

function escapeXml(s) {
  return String(s ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

/** Pan / zoom / scroll navigation for the stalker CFG viewport. */
const stalkGraphNav = {
  el: null,
  world: null,
  mini: null,
  miniVp: null,
  graphW: 1,
  graphH: 1,
  scale: 1,
  padX: 0,
  padY: 0,
  contentW: 1,
  contentH: 1,
  dragging: false,
  lastX: 0,
  lastY: 0,
  toolsBound: false,
  elAbort: null,
  miniAbort: null,

  attach(el, world, graphW, graphH) {
    this.el = el;
    this.world = world;
    this.graphW = Math.max(1, graphW);
    this.graphH = Math.max(1, graphH);
    this.mini = document.getElementById('stalk-minimap');
    this.miniVp = this.mini?.querySelector('.stalk-minimap-viewport') || null;
    this.bindToolsOnce();
    this.bindViewport(el);
    this.bindMinimap();
    this.applyScale(this.scale, { keepCenter: false });
    this.syncMinimap();
  },

  bindToolsOnce() {
    if (this.toolsBound) return;
    this.toolsBound = true;
    const self = this;
    document.getElementById('stalk-zoom-in')?.addEventListener('click', () => self.zoomBy(1.2));
    document.getElementById('stalk-zoom-out')?.addEventListener('click', () => self.zoomBy(1 / 1.2));
    document.getElementById('stalk-zoom-reset')?.addEventListener('click', () => self.setZoom(1));
    document.getElementById('stalk-zoom-fit')?.addEventListener('click', () => self.fit());
  },

  bindViewport(el) {
    this.elAbort?.abort();
    this.elAbort = new AbortController();
    const { signal } = this.elAbort;
    const self = this;
    self.pendingPan = false;
    self.panMoved = false;

    el.addEventListener('pointerdown', (ev) => {
      if (ev.button !== 0 && ev.button !== 1) return;
      if (ev.target.closest('button, a, input, select, textarea, .stalk-ctx-menu')) return;
      // On a node: wait for movement before panning so click/contextmenu still work
      self.pendingPan = true;
      self.panMoved = false;
      self.dragging = false;
      self.lastX = ev.clientX;
      self.lastY = ev.clientY;
      self.fromNode = !!ev.target.closest('.stalk-node-g');
      el.focus({ preventScroll: true });
      try { el.setPointerCapture(ev.pointerId); } catch { /* ignore */ }
      if (!self.fromNode) {
        self.dragging = true;
        el.classList.add('is-panning');
        ev.preventDefault();
      }
    }, { signal });

    el.addEventListener('pointermove', (ev) => {
      if (!self.pendingPan && !self.dragging) return;
      const dx = ev.clientX - self.lastX;
      const dy = ev.clientY - self.lastY;
      if (!self.dragging) {
        if (Math.hypot(dx, dy) < 5) return;
        self.dragging = true;
        self.panMoved = true;
        el.classList.add('is-panning');
      }
      self.lastX = ev.clientX;
      self.lastY = ev.clientY;
      el.scrollLeft -= dx;
      el.scrollTop -= dy;
      self.syncMinimap();
    }, { signal });

    const endDrag = (ev) => {
      const wasDrag = self.dragging;
      self.pendingPan = false;
      self.dragging = false;
      el.classList.remove('is-panning');
      try { el.releasePointerCapture(ev.pointerId); } catch { /* ignore */ }
      // Suppress click after a real pan
      if (wasDrag && self.panMoved) self.suppressClickUntil = Date.now() + 80;
    };
    el.addEventListener('pointerup', endDrag, { signal });
    el.addEventListener('pointercancel', endDrag, { signal });

    el.addEventListener('wheel', (ev) => {
      if (ev.ctrlKey || ev.metaKey) {
        ev.preventDefault();
        const factor = ev.deltaY < 0 ? 1.12 : 1 / 1.12;
        self.zoomAt(factor, ev.clientX, ev.clientY);
        return;
      }
      if (ev.shiftKey) {
        ev.preventDefault();
        el.scrollLeft += ev.deltaY !== 0 ? ev.deltaY : ev.deltaX;
        self.syncMinimap();
        return;
      }
      // Native vertical scroll; also map trackpad horizontal
      if (Math.abs(ev.deltaX) > Math.abs(ev.deltaY)) {
        ev.preventDefault();
        el.scrollLeft += ev.deltaX;
        self.syncMinimap();
      }
    }, { passive: false, signal });

    el.addEventListener('scroll', () => self.syncMinimap(), { signal });

    el.addEventListener('keydown', (ev) => {
      const step = ev.shiftKey ? 120 : 48;
      let handled = true;
      if (ev.key === 'ArrowLeft') el.scrollLeft -= step;
      else if (ev.key === 'ArrowRight') el.scrollLeft += step;
      else if (ev.key === 'ArrowUp') el.scrollTop -= step;
      else if (ev.key === 'ArrowDown') el.scrollTop += step;
      else if (ev.key === '+' || ev.key === '=') self.zoomBy(1.15);
      else if (ev.key === '-' || ev.key === '_') self.zoomBy(1 / 1.15);
      else if (ev.key === '0') self.setZoom(1);
      else if (ev.key === 'f' || ev.key === 'F') self.fit();
      else handled = false;
      if (handled) {
        ev.preventDefault();
        self.syncMinimap();
      }
    }, { signal });
  },

  bindMinimap() {
    this.miniAbort?.abort();
    this.mini = document.getElementById('stalk-minimap');
    this.miniVp = this.mini?.querySelector('.stalk-minimap-viewport') || null;
    if (!this.mini) return;
    this.miniAbort = new AbortController();
    const { signal } = this.miniAbort;
    const self = this;
    const jump = (ev) => self.jumpMinimap(ev);
    this.mini.addEventListener('pointerdown', jump, { signal });
    this.mini.addEventListener('pointermove', (ev) => {
      if (ev.buttons === 1) jump(ev);
    }, { signal });
  },

  setZoom(scale) {
    this.applyScale(Math.min(3, Math.max(0.25, scale)), { keepCenter: true });
  },

  zoomBy(factor) {
    this.setZoom(this.scale * factor);
  },

  zoomAt(factor, clientX, clientY) {
    if (!this.el || !this.world) return;
    const rect = this.el.getBoundingClientRect();
    const padX = this.padX || 0;
    const padY = this.padY || 0;
    // Cursor in unpadded content space
    const contentX = clientX - rect.left + this.el.scrollLeft - padX;
    const contentY = clientY - rect.top + this.el.scrollTop - padY;
    const prev = this.scale;
    const next = Math.min(3, Math.max(0.25, prev * factor));
    if (next === prev) return;
    this.applyScale(next, { keepCenter: false });
    const newPadX = this.padX || 0;
    const newPadY = this.padY || 0;
    this.el.scrollLeft = newPadX + contentX * (next / prev) - (clientX - rect.left);
    this.el.scrollTop = newPadY + contentY * (next / prev) - (clientY - rect.top);
    this.syncMinimap();
  },

  applyScale(scale, { keepCenter }) {
    if (!this.el || !this.world) return;
    const prev = this.scale || 1;
    const cx = this.el.scrollLeft + this.el.clientWidth / 2;
    const cy = this.el.scrollTop + this.el.clientHeight / 2;
    this.scale = scale;
    const w = this.graphW * scale;
    const h = this.graphH * scale;
    // Letterbox so a small/fitted graph sits in the middle of the panel, not a corner
    const canvasW = Math.max(w, this.el.clientWidth);
    const canvasH = Math.max(h, this.el.clientHeight);
    const padX = Math.max(0, (canvasW - w) / 2);
    const padY = Math.max(0, (canvasH - h) / 2);
    this.world.style.width = `${canvasW}px`;
    this.world.style.height = `${canvasH}px`;
    this.world.style.padding = `${padY}px ${padX}px`;
    this.world.style.boxSizing = 'border-box';
    const svg = this.world.querySelector('svg');
    if (svg) {
      svg.setAttribute('width', String(w));
      svg.setAttribute('height', String(h));
      svg.setAttribute('viewBox', `0 0 ${this.graphW} ${this.graphH}`);
      svg.style.display = 'block';
    }
    // Store pad so pan/center/minimap can account for letterboxing
    this.padX = padX;
    this.padY = padY;
    this.contentW = w;
    this.contentH = h;
    if (keepCenter && prev > 0) {
      this.el.scrollLeft = cx * (scale / prev) - this.el.clientWidth / 2;
      this.el.scrollTop = cy * (scale / prev) - this.el.clientHeight / 2;
    }
    this.updateLabel();
    this.syncMinimap();
  },

  fit() {
    if (!this.el) return;
    const pad = 36;
    const vw = Math.max(80, this.el.clientWidth - pad);
    const vh = Math.max(80, this.el.clientHeight - pad);
    const sx = vw / this.graphW;
    const sy = vh / this.graphH;
    // Prefer filling the panel; allow slight upscale so small graphs aren't tiny
    this.applyScale(Math.min(1.75, Math.max(0.35, Math.min(sx, sy))), { keepCenter: false });
    this.centerOn(this.graphW / 2, this.graphH / 2);
  },

  /** Center the viewport on a point in graph (unscaled) coordinates. */
  centerOn(graphX, graphY) {
    if (!this.el) return;
    const padX = this.padX || 0;
    const padY = this.padY || 0;
    const x = padX + graphX * this.scale;
    const y = padY + graphY * this.scale;
    this.el.scrollLeft = Math.max(0, x - this.el.clientWidth / 2);
    this.el.scrollTop = Math.max(0, y - this.el.clientHeight / 2);
    this.syncMinimap();
  },

  updateLabel() {
    const label = document.getElementById('stalk-zoom-label');
    if (label) label.textContent = `${Math.round(this.scale * 100)}%`;
  },

  syncMinimap() {
    if (!this.el || !this.mini) return;
    this.miniVp = this.mini.querySelector('.stalk-minimap-viewport') || this.miniVp;
    if (!this.miniVp) return;
    const mw = this.mini.clientWidth;
    const mh = this.mini.clientHeight;
    if (mw < 4 || mh < 4) return;
    // Minimap shows the graph content (not letterbox padding)
    const contentW = this.graphW * this.scale;
    const contentH = this.graphH * this.scale;
    const s = Math.min(mw / Math.max(contentW, 1), mh / Math.max(contentH, 1));
    const ox = (mw - contentW * s) / 2;
    const oy = (mh - contentH * s) / 2;
    const padX = this.padX || 0;
    const padY = this.padY || 0;
    const viewX = Math.max(0, this.el.scrollLeft - padX);
    const viewY = Math.max(0, this.el.scrollTop - padY);
    const vx = viewX * s + ox;
    const vy = viewY * s + oy;
    const vw = Math.min(this.el.clientWidth, contentW) * s;
    const vh = Math.min(this.el.clientHeight, contentH) * s;
    this.miniVp.style.left = `${Math.max(0, vx)}px`;
    this.miniVp.style.top = `${Math.max(0, vy)}px`;
    this.miniVp.style.width = `${Math.max(6, vw)}px`;
    this.miniVp.style.height = `${Math.max(6, vh)}px`;
  },

  jumpMinimap(ev) {
    if (!this.el || !this.mini) return;
    const rect = this.mini.getBoundingClientRect();
    const mx = ev.clientX - rect.left;
    const my = ev.clientY - rect.top;
    const mw = this.mini.clientWidth;
    const mh = this.mini.clientHeight;
    const contentW = this.graphW * this.scale;
    const contentH = this.graphH * this.scale;
    const s = Math.min(mw / Math.max(contentW, 1), mh / Math.max(contentH, 1));
    const ox = (mw - contentW * s) / 2;
    const oy = (mh - contentH * s) / 2;
    const gx = (mx - ox) / s; // scaled content coords
    const gy = (my - oy) / s;
    const padX = this.padX || 0;
    const padY = this.padY || 0;
    this.el.scrollLeft = padX + gx - this.el.clientWidth / 2;
    this.el.scrollTop = padY + gy - this.el.clientHeight / 2;
    this.syncMinimap();
  },
};

/** Vertical CFG: crash spine down the center, forks to the sides. */
function renderStalkGraph(blocks, edges) {
  const el = document.getElementById('stalker-graph');
  const mini = document.getElementById('stalk-minimap');
  if (!blocks?.length) {
    el.innerHTML = '<p class="stalk-empty">No graph yet — pick a project or run a fuzz campaign.</p>';
    if (mini) mini.innerHTML = '';
    return;
  }

  const nodeW = 176;
  const nodeH = 80;
  const gapY = 52;
  const forkX = 210;
  const pad = 56;
  const byId = Object.fromEntries(blocks.map((b) => [b.id, b]));
  const edgeList = edges || [];

  let spine = blocks
    .filter((b) => b.onCrashPath)
    .sort((a, b) => (a.pathIndex ?? 99) - (b.pathIndex ?? 99));

  if (!spine.length) {
    const entry = blocks.find((b) => b.id === '__entry') || blocks[0];
    spine = [entry];
    const crash = blocks.find((b) => b.kind === 'crash');
    if (crash) spine.push(crash);
  }

  const spineIds = new Set(spine.map((b) => b.id));
  const positions = {};

  // Lay out in relative coords first (spine at x=0), then center + normalize
  spine.forEach((b, i) => {
    positions[b.id] = { x: 0, y: i * (nodeH + gapY) };
  });

  const placeChain = (startId, x, startY) => {
    let current = startId;
    let y = startY;
    const seen = new Set([startId]);
    while (current) {
      const nextEdge = edgeList.find((e) =>
        e.from === current && !spineIds.has(e.to) && !positions[e.to] && !seen.has(e.to));
      if (!nextEdge || !byId[nextEdge.to]) break;
      y += nodeH + gapY;
      positions[nextEdge.to] = { x, y };
      seen.add(nextEdge.to);
      current = nextEdge.to;
    }
  };

  spine.forEach((parent) => {
    const forks = edgeList.filter((e) => e.from === parent.id && !spineIds.has(e.to));
    // Alternate left/right starting with LEFT so the crash spine isn't shoved right
    forks.forEach((e, ki) => {
      if (!byId[e.to] || positions[e.to]) return;
      const side = ki % 2 === 0 ? -1 : 1;
      const col = Math.floor(ki / 2) + 1;
      const x = side * col * forkX;
      const y = positions[parent.id].y + (nodeH + gapY);
      positions[e.to] = { x, y };
      placeChain(e.to, x, y);
    });
  });

  let orphanRow = 0;
  blocks.forEach((b) => {
    if (positions[b.id]) return;
    positions[b.id] = {
      x: -forkX,
      y: spine.length * (nodeH + gapY) + orphanRow * (nodeH + 24),
    };
    orphanRow += 1;
  });

  // Normalize: shift bbox so content is padded and canvas is tight (no dead corner)
  const xs = Object.values(positions).map((p) => p.x);
  const ys = Object.values(positions).map((p) => p.y);
  const minX = Math.min(...xs);
  const minY = Math.min(...ys);
  const maxX = Math.max(...xs);
  const maxY = Math.max(...ys);
  const shiftX = pad - minX;
  const shiftY = pad - minY;
  for (const p of Object.values(positions)) {
    p.x += shiftX;
    p.y += shiftY;
  }
  const width = (maxX - minX) + nodeW + pad * 2;
  const height = (maxY - minY) + nodeH + pad * 2;
  const spineX = positions[spine[0]?.id]?.x ?? pad;

  const edgePaths = edgeList.map((e) => {
    const a = positions[e.from];
    const b = positions[e.to];
    if (!a || !b) return '';
    const x1 = a.x + nodeW / 2;
    const y1 = a.y + nodeH;
    const x2 = b.x + nodeW / 2;
    const y2 = b.y;
    const midY = (y1 + y2) / 2;
    const d = `M${x1},${y1} C${x1},${midY} ${x2},${midY} ${x2},${y2}`;
    const toCrash = byId[e.to]?.kind === 'crash';
    const cls = e.onCrashPath ? (toCrash ? 'crash' : 'path') : (e.taken ? 'path' : 'miss');
    const label = e.label
      ? `<text class="stalk-edge-label" x="${(x1 + x2) / 2 + 10}" y="${midY}">${escapeXml(e.label)}</text>`
      : '';
    return `<path class="stalk-edge ${cls}" d="${d}" marker-end="url(#arrow-${cls})" />${label}`;
  }).join('');

  const caption = `<text class="stalk-path-caption" x="${spineX + nodeW / 2}" y="${Math.max(16, pad - 20)}" text-anchor="middle">Crash path ↓</text>`;

  const nodes = blocks.map((b) => {
    const p = positions[b.id];
    if (!p) return '';
    const title = b.label || b.id;
    const addr = b.address || '';
    const detail = b.detail || '';
    const skull = b.kind === 'crash'
      ? `<text x="${p.x + nodeW - 18}" y="${p.y + 18}" font-size="14">☠</text>`
      : '';
    const step = b.onCrashPath && b.pathIndex >= 0
      ? `<text class="stalk-step" x="${p.x + 8}" y="${p.y + 14}">${b.pathIndex + 1}</text>`
      : '';
    const forkTag = !b.onCrashPath
      ? `<text class="stalk-fork-tag" x="${p.x + nodeW - 8}" y="${p.y + 14}" text-anchor="end">fork</text>`
      : '';
    return `<g class="stalk-node-g" data-id="${escapeXml(b.id)}">
      <rect class="stalk-node ${b.kind}" x="${p.x}" y="${p.y}" width="${nodeW}" height="${nodeH}" rx="8" />
      ${step}${skull}${forkTag}
      <text class="stalk-node-label" x="${p.x + nodeW / 2}" y="${p.y + 30}">${escapeXml(title)}</text>
      <text class="stalk-node-sub" x="${p.x + nodeW / 2}" y="${p.y + 46}">${escapeXml(addr)}</text>
      <text class="stalk-node-detail" x="${p.x + nodeW / 2}" y="${p.y + 64}">${escapeXml(detail.length > 30 ? `${detail.slice(0, 30)}…` : detail)}</text>
      <title>${escapeXml(`${title}\n${addr}\n${detail}\n(click to inspect · right-click for RE)`)}</title>
    </g>`;
  }).join('');

  const svgInner = `<svg viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <marker id="arrow-path" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 0 L 10 5 L 0 10 z" fill="#3d8bfd" />
      </marker>
      <marker id="arrow-crash" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 0 L 10 5 L 0 10 z" fill="#ff3b4a" />
      </marker>
      <marker id="arrow-miss" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 0 L 10 5 L 0 10 z" fill="#6b7280" />
      </marker>
    </defs>
    ${caption}${edgePaths}${nodes}
  </svg>`;
  el.innerHTML = `<div class="stalker-graph-world" id="stalker-graph-world">${svgInner}</div>`;
  if (mini) {
    mini.innerHTML =
      `<svg viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg">${edgePaths}${nodes}</svg>` +
      `<div class="stalk-minimap-viewport"></div>`;
  }
  const world = document.getElementById('stalker-graph-world');
  stalkGraphNav.scale = 1;
  stalkGraphNav.attach(el, world, width, height);
  // Fit + center the crash spine in the viewport (not stuck in a corner)
  requestAnimationFrame(() => {
    stalkGraphNav.fit();
    stalkGraphNav.centerOn(spineX + nodeW / 2, height / 2);
  });
  bindStalkGraphInteractions(el, blocks, edges || []);
}

let stalkInspect = { blocks: [], edges: [], selectedId: null };

function bindStalkGraphInteractions(el, blocks, edges) {
  stalkInspect.blocks = blocks || [];
  stalkInspect.edges = edges || [];
  if (stalkInspect.selectedId) {
    const still = stalkInspect.blocks.some((b) => b.id === stalkInspect.selectedId);
    if (still) highlightStalkNode(stalkInspect.selectedId);
    else closeBlockInspector();
  }

  el.querySelectorAll('.stalk-node-g').forEach((g) => {
    g.addEventListener('click', (ev) => {
      if (stalkGraphNav.suppressClickUntil && Date.now() < stalkGraphNav.suppressClickUntil) return;
      ev.stopPropagation();
      openBlockInspector(g.dataset.id);
    });
    g.addEventListener('contextmenu', (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      showBlockContextMenu(ev.clientX, ev.clientY, g.dataset.id);
    });
  });

  el.addEventListener('click', () => hideBlockContextMenu());
}

function highlightStalkNode(id) {
  const el = document.getElementById('stalker-graph');
  el?.querySelectorAll('.stalk-node-g').forEach((g) => {
    g.classList.toggle('selected', g.dataset.id === id);
  });
  stalkInspect.selectedId = id;
}

function hideBlockContextMenu() {
  const menu = document.getElementById('stalk-ctx-menu');
  if (menu) {
    menu.classList.add('hidden');
    menu.innerHTML = '';
  }
}

function showBlockContextMenu(x, y, id) {
  const block = stalkInspect.blocks.find((b) => b.id === id);
  if (!block) return;
  const menu = document.getElementById('stalk-ctx-menu');
  if (!menu) return;
  highlightStalkNode(id);
  const items = [
    { action: 'inspect', label: 'Inspect block (RE)' },
    { action: 'copy-addr', label: 'Copy address' },
    { action: 'copy-label', label: 'Copy label' },
  ];
  if (block.prefix) items.push({ action: 'copy-prefix', label: 'Copy wire prefix' });
  if (block.crashId) {
    items.push({ sep: true });
    items.push({ action: 'open-crash', label: 'Open crash investigation' });
  }
  items.push({ sep: true });
  items.push({ action: 'copy-re', label: 'Copy RE notes' });

  menu.innerHTML = items.map((it) => {
    if (it.sep) return '<div class="sep"></div>';
    return `<button type="button" role="menuitem" data-action="${it.action}">${escapeAttr(it.label)}</button>`;
  }).join('');
  menu.classList.remove('hidden');
  const pad = 8;
  const mw = menu.offsetWidth || 180;
  const mh = menu.offsetHeight || 160;
  menu.style.left = `${Math.min(x, window.innerWidth - mw - pad)}px`;
  menu.style.top = `${Math.min(y, window.innerHeight - mh - pad)}px`;

  menu.querySelectorAll('button').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const action = btn.dataset.action;
      hideBlockContextMenu();
      if (action === 'inspect') openBlockInspector(id);
      else if (action === 'copy-addr') {
        await navigator.clipboard.writeText(block.address || '');
      } else if (action === 'copy-label') {
        await navigator.clipboard.writeText(block.label || '');
      } else if (action === 'copy-prefix') {
        await navigator.clipboard.writeText(block.prefix || '');
      } else if (action === 'copy-re') {
        const text = formatBlockReNotes(block);
        await navigator.clipboard.writeText(text);
      } else if (action === 'open-crash' && block.crashId) {
        crashState.pendingSelectId = block.crashId;
        switchView('crashes');
      }
    });
  });
}

function formatBlockReNotes(b) {
  const lines = [
    `# ${b.label} (${b.role || b.kind})`,
    `Address: ${b.address || '—'}`,
    b.module ? `Module: ${b.module}` : null,
    b.detail ? `Detail: ${b.detail}` : null,
    b.command ? `Command: ${b.command}` : null,
    b.prefix ? `Prefix: ${b.prefix}` : null,
    b.mutator ? `Mutator: ${b.mutator}` : null,
    b.exceptionHint ? `Exception: ${b.exceptionHint}` : null,
    b.rip ? `RIP: ${b.rip}` : null,
    b.rsp ? `RSP: ${b.rsp}` : null,
    b.faultModule ? `Fault module: ${b.faultModule}` : null,
    '',
    'RE hints:',
    ...(b.reHints || []).map((h) => `- ${h}`),
  ].filter((x) => x != null);
  return lines.join('\n');
}

function edgeSummary(id) {
  const incoming = stalkInspect.edges.filter((e) => e.to === id);
  const outgoing = stalkInspect.edges.filter((e) => e.from === id);
  return { incoming, outgoing };
}

function openBlockInspector(id) {
  const block = stalkInspect.blocks.find((b) => b.id === id);
  const panel = document.getElementById('stalk-block-inspector');
  const title = document.getElementById('stalk-insp-title');
  const body = document.getElementById('stalk-insp-body');
  if (!block || !panel || !body) return;
  hideBlockContextMenu();
  highlightStalkNode(id);
  panel.classList.remove('hidden');
  const { incoming, outgoing } = edgeSummary(id);
  const sev = (block.severity || '').toLowerCase();
  title.textContent = `${block.label} · ${block.role || block.kind}`;

  const inEdges = incoming.map((e) =>
    `${e.from}${e.label ? ` (${e.label})` : ''}${e.taken ? '' : ' · miss'}`).join(', ') || '—';
  const outEdges = outgoing.map((e) =>
    `${e.to}${e.label ? ` (${e.label})` : ''}${e.taken ? '' : ' · miss'}`).join(', ') || '—';

  body.innerHTML = `
    <p class="stalk-insp-why">${escapeAttr(block.detail || 'No detail for this block.')}</p>
    <dl class="stalk-insp-meta">
      <dt>Kind</dt><dd><span class="severity-${sev || 'low'}">${escapeAttr(block.kind)}</span>
        ${block.onCrashPath ? ' · <strong>crash path</strong>' : ''}
        ${block.pathIndex >= 0 ? ` · step ${block.pathIndex}` : ''}</dd>
      <dt>Address</dt><dd><code>${escapeAttr(block.address || '—')}</code></dd>
      ${block.module ? `<dt>Module</dt><dd><code>${escapeAttr(block.module)}</code></dd>` : ''}
      ${block.command ? `<dt>Command</dt><dd><code>${escapeAttr(block.command)}</code></dd>` : ''}
      ${block.prefix ? `<dt>Prefix</dt><dd><code>${escapeAttr(block.prefix)}</code></dd>` : ''}
      ${block.preamble ? `<dt>Preamble</dt><dd><code>${escapeAttr(block.preamble)}</code></dd>` : ''}
      ${block.expectResponse ? `<dt>Expect</dt><dd><code>${escapeAttr(block.expectResponse)}</code></dd>` : ''}
      ${block.model ? `<dt>Model</dt><dd><code>${escapeAttr(block.model)}</code></dd>` : ''}
      ${block.mutator ? `<dt>Mutator</dt><dd><code>${escapeAttr(block.mutator)}</code></dd>` : ''}
      ${block.hitCount != null ? `<dt>Hits</dt><dd>${block.hitCount}</dd>` : ''}
      ${block.exceptionHint ? `<dt>Exception</dt><dd><code>${escapeAttr(block.exceptionHint)}</code></dd>` : ''}
      ${block.crashClass ? `<dt>Class</dt><dd><code>${escapeAttr(block.crashClass)}</code>${sev ? ` · ${sev}` : ''}</dd>` : ''}
      ${block.clusterKey ? `<dt>Cluster</dt><dd><code>${escapeAttr(block.clusterKey)}</code></dd>` : ''}
      <dt>Incoming</dt><dd><code>${escapeAttr(inEdges)}</code></dd>
      <dt>Outgoing</dt><dd><code>${escapeAttr(outEdges)}</code></dd>
    </dl>
    ${(block.rip || block.rsp || block.rbp) ? `<div class="stalk-insp-regs">
      ${block.rip ? `<div><span>RIP</span>${escapeAttr(block.rip)}</div>` : ''}
      ${block.rsp ? `<div><span>RSP</span>${escapeAttr(block.rsp)}</div>` : ''}
      ${block.rbp ? `<div><span>RBP</span>${escapeAttr(block.rbp)}</div>` : ''}
      ${block.faultModule ? `<div><span>MOD</span>${escapeAttr(block.faultModule)}</div>` : ''}
    </div>` : ''}
    ${(block.reHints || []).length ? `<ol class="stalk-insp-hints">${
      block.reHints.map((h) => `<li>${escapeAttr(h)}</li>`).join('')
    }</ol>` : ''}
    ${block.asciiPreview ? `<p class="label">Payload ASCII ${block.inputLength != null ? `(${block.inputLength}B)` : ''}</p>
      <pre class="stalk-insp-payload">${escapeAttr(block.asciiPreview)}</pre>` : ''}
    ${block.hexPreview ? `<p class="label">Payload hex</p>
      <pre class="stalk-insp-payload">${escapeAttr(block.hexPreview)}</pre>` : ''}
    <div class="stalk-insp-actions btn-row wrap">
      <button type="button" class="btn" data-insp="copy-re">Copy RE notes</button>
      <button type="button" class="btn" data-insp="copy-addr">Copy address</button>
      ${block.crashId ? `<button type="button" class="btn primary" data-insp="open-crash">Open crash</button>` : ''}
      ${block.kind === 'crash' || block.isMutate ? `<button type="button" class="btn" data-insp="crashes">Crashes tab</button>` : ''}
    </div>`;

  body.querySelectorAll('[data-insp]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const a = btn.dataset.insp;
      if (a === 'copy-re') await navigator.clipboard.writeText(formatBlockReNotes(block));
      if (a === 'copy-addr') await navigator.clipboard.writeText(block.address || '');
      if (a === 'open-crash' && block.crashId) {
        crashState.pendingSelectId = block.crashId;
        switchView('crashes');
      }
      if (a === 'crashes') switchView('crashes');
    });
  });
}

function closeBlockInspector() {
  const panel = document.getElementById('stalk-block-inspector');
  panel?.classList.add('hidden');
  stalkInspect.selectedId = null;
  document.getElementById('stalker-graph')?.querySelectorAll('.stalk-node-g.selected')
    .forEach((g) => g.classList.remove('selected'));
  hideBlockContextMenu();
}

function timelinePointKey(p, index) {
  if (p.crashId) return `crash:${p.crashId}`;
  const kind = p.kind || (p.crashed ? 'crash' : p.newEdges > 0 ? 'novel' : 'hit');
  return `iter:${p.iteration}:${kind}:${p.label || ''}:${index ?? p.index ?? 0}`;
}

function rememberTimelineCrashIds(points) {
  for (const p of points || []) {
    if (p.crashId != null && p.iteration != null)
      stalkCrashIdByIteration.set(Number(p.iteration), p.crashId);
  }
  for (const p of stalkLiveTimeline) {
    if (!p.crashId && stalkCrashIdByIteration.has(Number(p.iteration)))
      p.crashId = stalkCrashIdByIteration.get(Number(p.iteration));
  }
}

function updateTimelineFollowUi() {
  const btn = document.getElementById('stalk-follow-live');
  const label = document.getElementById('stalk-timeline-selection');
  if (!btn || !label) return;
  if (stalkFollowLive || !stalkSelection) {
    btn.classList.add('hidden');
    label.classList.add('hidden');
    label.textContent = '';
    return;
  }
  btn.classList.remove('hidden');
  label.classList.remove('hidden');
  const kind = stalkSelection.kind || 'hit';
  const crashBit = stalkSelection.crashId
    ? ` · ${String(stalkSelection.crashId).slice(0, 8)}…`
    : '';
  label.textContent = `Pinned #${stalkSelection.iteration} ${stalkSelection.label || ''} (${kind})${crashBit}`.trim();
}

function mergeTimeline(serverPoints) {
  if (Array.isArray(serverPoints))
    stalkServerTimeline = serverPoints;
  rememberTimelineCrashIds(stalkServerTimeline);
  rememberTimelineCrashIds(stalkLiveTimeline);
  if (!stalkLiveTimeline.length)
    return (stalkServerTimeline || []).slice(-200);
  return [...(stalkServerTimeline || []), ...stalkLiveTimeline].slice(-200);
}

function ensureTimelineClickDelegation() {
  const el = document.getElementById('stalk-timeline');
  if (!el || stalkTimelineClickBound) return;
  stalkTimelineClickBound = true;
  el.addEventListener('click', (ev) => {
    const bar = ev.target.closest?.('.bar');
    if (!bar || !el.contains(bar)) return;
    ev.preventDefault();
    const idx = Number(bar.dataset.index);
    const point = stalkRenderedTimeline[idx];
    if (point) {
      selectTimelinePoint(point, idx).catch((err) => {
        console.error('Timeline selection failed', err);
        const notes = document.getElementById('stalk-notes');
        if (notes)
          notes.innerHTML = `<li class="warn">Timeline pin failed: ${escapeXml(err.message || String(err))}</li>`;
      });
    }
  });
}

function renderTimeline(points) {
  const el = document.getElementById('stalk-timeline');
  const end = document.getElementById('stalk-timeline-end');
  if (!el || !end) return;
  ensureTimelineClickDelegation();
  const list = (points || []).slice(-200).map((p, i) => {
    const kind = p.kind || (p.crashed ? 'crash' : (p.newEdges || p.newEdgeCount) > 0 ? 'novel' : 'hit');
    const crashId = p.crashId || stalkCrashIdByIteration.get(Number(p.iteration)) || null;
    return { ...p, kind, crashId, index: p.index ?? i };
  });
  stalkRenderedTimeline = list;
  rememberTimelineCrashIds(list);
  if (!list.length) {
    el.innerHTML = '';
    end.textContent = 'NOW';
    updateTimelineFollowUi();
    return;
  }
  const selectedKey = stalkSelection?.key;
  el.innerHTML = list.map((p, i) => {
    const kind = p.kind;
    const h = kind === 'crash' ? 100 : kind === 'novel' ? 70 : kind === 'miss' ? 22 : 45;
    const key = timelinePointKey(p, i);
    const selected = selectedKey && key === selectedKey ? ' selected' : '';
    const title = `#${p.iteration} ${p.label || ''} (${kind}) — click to inspect`;
    return `<button type="button" class="bar ${kind}${selected}" style="height:${h}%"
      data-index="${i}" data-iteration="${p.iteration}" data-kind="${kind}"
      data-label="${escapeXml(p.label || '')}"
      data-crash-id="${escapeXml(p.crashId || '')}"
      title="${escapeXml(title)}"
      aria-label="${escapeXml(title)}"
      role="option" aria-selected="${selected ? 'true' : 'false'}"></button>`;
  }).join('');
  const last = list[list.length - 1];
  if (!stalkFollowLive && stalkSelection)
    end.textContent = `PINNED #${stalkSelection.iteration}`;
  else
    end.textContent = last.crashed || last.kind === 'crash' ? 'NOW (CRASH)' : 'NOW';
  updateTimelineFollowUi();
}

async function resolveCrashIdForIteration(iteration) {
  if (stalkCrashIdByIteration.has(Number(iteration)))
    return stalkCrashIdByIteration.get(Number(iteration));
  if (!stalkProject) return null;
  try {
    const crashes = await api.get(`/api/crashes?project=${encodeURIComponent(stalkProject)}`);
    for (const c of crashes || []) {
      if (c.iteration != null && c.id)
        stalkCrashIdByIteration.set(Number(c.iteration), c.id);
    }
    return stalkCrashIdByIteration.get(Number(iteration)) || null;
  } catch {
    return null;
  }
}

function applyIterationSelectionNote(point) {
  const notes = document.getElementById('stalk-notes');
  if (!notes) return;
  const kind = point.kind || 'hit';
  notes.innerHTML = [
    `<li>Timeline selection: iteration <strong>#${point.iteration}</strong> (${kind}).</li>`,
    point.label ? `<li>Label / mutator: <code>${point.label}</code></li>` : '',
    (point.newEdges || point.newEdgeCount)
      ? `<li>New edges this case: <strong>${point.newEdges || point.newEdgeCount}</strong></li>`
      : '',
    '<li>Live updates paused — click <strong>Follow live</strong> to resume.</li>',
  ].filter(Boolean).join('');
  document.getElementById('stalk-divergence').textContent =
    kind === 'novel' ? (point.label || `iter #${point.iteration}`) : (document.getElementById('stalk-divergence').textContent || '—');
}

function highlightCrashLogRow(crashId) {
  const log = document.getElementById('stalk-crash-log');
  if (!log) return;
  log.querySelectorAll('tr.crash-row').forEach((row) => {
    row.classList.toggle('selected', !!crashId && row.dataset.id === crashId);
  });
}

async function selectTimelinePoint(point, index) {
  const kind = point.kind || (point.crashed ? 'crash' : 'hit');
  let crashId = point.crashId || stalkCrashIdByIteration.get(Number(point.iteration)) || null;
  if ((kind === 'crash' || point.crashed) && !crashId)
    crashId = await resolveCrashIdForIteration(point.iteration);

  stalkFollowLive = false;
  stalkSelection = {
    key: timelinePointKey({ ...point, crashId, kind }, index),
    iteration: point.iteration,
    kind,
    label: point.label || '',
    crashId,
    index,
  };
  // Paint pin/selection immediately (before network) so Follow live + bar highlight show up.
  renderTimeline(stalkRenderedTimeline);
  updateTimelineFollowUi();

  if (crashId) {
    await loadDashboard({ crashId, applyWidgets: true, force: true });
    highlightCrashLogRow(crashId);
  } else {
    applyIterationSelectionNote(point);
    updateTimelineFollowUi();
  }
}

function followStalkLive() {
  stalkFollowLive = true;
  stalkSelection = null;
  updateTimelineFollowUi();
  loadDashboard({ applyWidgets: true, followLive: true }).catch(() => {});
}

function applyDashboardWidgets(data, { selectedCrashId = null } = {}) {
  document.getElementById('stalk-target').textContent = data.targetName || data.project;
  document.getElementById('stalk-pid').textContent = data.pid ?? '—';
  document.getElementById('stalk-arch').textContent = data.arch || '—';
  document.getElementById('stalk-mode').textContent = data.mode || '—';
  const st = document.getElementById('stalk-status');
  st.textContent = data.status || 'Idle';
  st.className = statusClass(data.status);

  document.getElementById('stalk-session').innerHTML = `
    <dt>Session</dt><dd>${data.sessionId || '—'}</dd>
    <dt>Started</dt><dd>${data.sessionStartedAt ? new Date(data.sessionStartedAt).toLocaleString() : '—'}</dd>
    <dt>Input</dt><dd>${data.fuzzerInput || '—'}</dd>
    <dt>Crash time</dt><dd>${data.crashTime || '—'}</dd>
    <dt>Exception</dt><dd>${data.exception || '—'}</dd>
    <dt>Address</dt><dd>${data.crashAddress || '—'}</dd>
    <dt>Thread</dt><dd>${data.threadId || '—'}</dd>`;

  const pct = data.coveragePercent ?? 0;
  document.getElementById('stalk-coverage-ring').style.setProperty('--pct', pct);
  document.getElementById('stalk-coverage-pct').textContent = `${pct}%`;
  document.getElementById('stalk-coverage-label').textContent = data.coverageLabel || 'Coverage';
  document.getElementById('stalk-coverage-detail').textContent = data.coverageDetail || '';
  document.getElementById('stalk-coverage-stats').innerHTML = `
    <li>Path / BB units <strong>${data.currentBlocks}</strong></li>
    <li>BB edges <strong>${data.coverageEdges}</strong></li>
    <li>Corpus size <strong>${data.corpusSize}</strong></li>
    <li>DynamoRIO <strong>${data.dynamoRioAvailable ? 'Ready' : 'Missing'}</strong></li>`;

  document.getElementById('stalk-crash-summary').innerHTML = `
    <dt>Crash ID</dt><dd>${data.crashId || '—'}</dd>
    <dt>Hits</dt><dd>${data.crashHitCount ?? 0}</dd>
    <dt>Distance</dt><dd>${data.crashDistance ?? '—'} blocks</dd>
    <dt>Exception</dt><dd>${data.exception || '—'}</dd>
    <dt>Address</dt><dd>${data.crashAddress || '—'}</dd>`;

  const hot = document.getElementById('stalk-hot-blocks');
  hot.innerHTML = (data.topNewBlocks || []).length
    ? data.topNewBlocks.map((b) => `<li>${b.address} <span style="color:var(--muted)">×${b.hits}</span></li>`).join('')
    : '<li style="color:var(--muted);list-style:none">No hot blocks yet</li>';

  renderStalkGraph(data.blocks, data.edges);

  document.querySelector('#stalk-compare tbody').innerHTML = `
    <tr><td>Blocks hit</td><td>${data.baselineBlocks}</td><td>${data.currentBlocks}</td><td class="diff">+${data.diffBlocks}</td></tr>
    <tr><td>Edge coverage</td><td>${Math.max(0, data.coverageEdges - data.diffBlocks)}</td><td>${data.coverageEdges}</td><td class="diff">+${data.diffBlocks}</td></tr>
    <tr><td>Crashes</td><td>0</td><td>${data.crashes}</td><td class="diff">+${data.crashes}</td></tr>`;

  document.getElementById('stalk-divergence').textContent = data.firstDivergence || '—';
  document.getElementById('stalk-notes').innerHTML = (data.notes || []).map((n) => `<li>${n}</li>`).join('');

  const log = document.getElementById('stalk-crash-log');
  if (!(data.crashLog || []).length) {
    log.innerHTML = '<p class="stalk-empty">No crashes yet — start a fuzz run from the Fuzz tab.</p>';
  } else {
    const focusId = selectedCrashId || stalkSelection?.crashId || null;
    log.innerHTML = `<table><thead><tr>
      <th>ID</th><th>Sev</th><th>Class</th><th>Hits</th><th>Exception</th><th>Address</th><th>New cov</th><th>Input</th>
    </tr></thead><tbody>
      ${data.crashLog.map((c) => `<tr class="clickable crash-row${focusId && c.id === focusId ? ' selected' : ''}" data-id="${c.id}">
        <td><code>${c.shortId}</code></td>
        <td class="severity-${c.severity || 'low'}">${c.severity || '—'}</td>
        <td><code>${c.crashClass || '—'}</code></td>
        <td>${c.hits}</td>
        <td><code>${c.exception}</code></td>
        <td><code>${c.address}</code></td>
        <td>${c.newCoverage ? 'Yes' : 'No'}</td>
        <td><code>${c.inputName}</code></td>
      </tr>`).join('')}
    </tbody></table>`;
    log.querySelectorAll('tr.clickable').forEach((row) => {
      row.addEventListener('click', () => {
        const id = row.dataset.id;
        stalkFollowLive = false;
        stalkSelection = {
          key: `crash:${id}`,
          iteration: stalkSelection?.iteration ?? 0,
          kind: 'crash',
          label: 'crash-log',
          crashId: id,
          index: stalkSelection?.index ?? -1,
        };
        loadDashboard({ crashId: id, applyWidgets: true }).catch(() => {});
      });
    });
  }
}

async function loadDashboard(opts = {}) {
  const seq = ++stalkLoadSeq;
  // Explicit applyWidgets wins; otherwise follow-live (or a focused crashId) drives widgets.
  const applyWidgets = typeof opts.applyWidgets === 'boolean'
    ? opts.applyWidgets
    : (stalkFollowLive || !!opts.crashId || !!opts.force || !!opts.followLive);
  const crashId = opts.crashId
    || (!stalkFollowLive && stalkSelection?.crashId)
    || null;
  const wantFollowLive = !!opts.followLive || stalkFollowLive;

  const targets = (await api.get('/api/targets')).filter(isVisibleTarget);
  if (seq !== stalkLoadSeq) return;
  const tabs = document.getElementById('stalker-tabs');
  if (!targets.length) {
    tabs.innerHTML = '<span class="stalk-empty">No projects in projects/</span>';
    return;
  }

  if (!stalkProject || !targets.some((t) => t.name === stalkProject)) {
    stalkProject = targets.find((t) => t.name === 'vulnserver')?.name || targets[0].name;
  }

  tabs.innerHTML = targets.map((t) =>
    `<button type="button" data-project="${t.name}" class="${t.name === stalkProject ? 'active' : ''}">${t.name}</button>`).join('');
  tabs.querySelectorAll('button').forEach((btn) => {
    btn.addEventListener('click', () => {
      stalkProject = btn.dataset.project;
      stalkServerTimeline = [];
      stalkLiveTimeline = [];
      stalkCrashIdByIteration.clear();
      stalkFollowLive = true;
      stalkSelection = null;
      loadDashboard({ applyWidgets: true, followLive: true }).catch(() => {});
    });
  });

  const qs = crashId ? `?crashId=${encodeURIComponent(crashId)}` : '';
  const data = await api.get(`/api/stalk/${encodeURIComponent(stalkProject)}${qs}`);
  if (seq !== stalkLoadSeq) return;

  // Always refresh the bar strip; widgets are gated so in-flight live fetches cannot
  // clobber a pin that happened while this request was on the wire.
  renderTimeline(mergeTimeline(data.timeline || []));

  let canApply = applyWidgets;
  if (canApply && !stalkFollowLive) {
    const pinnedId = stalkSelection?.crashId || null;
    if (!crashId) {
      // Live/unfocused payload after user pinned — keep widgets frozen.
      canApply = false;
    } else if (pinnedId && String(pinnedId) !== String(crashId)) {
      canApply = false;
    }
  }
  if (canApply && wantFollowLive && !stalkFollowLive)
    canApply = false;

  if (canApply)
    applyDashboardWidgets(data, { selectedCrashId: crashId });
  else
    updateTimelineFollowUi();
}

document.getElementById('stalk-refresh')?.addEventListener('click', () => {
  loadDashboard({ applyWidgets: true, force: true }).catch(() => {});
});
document.getElementById('stalk-follow-live')?.addEventListener('click', () => followStalkLive());
document.getElementById('stalk-insp-close')?.addEventListener('click', () => closeBlockInspector());
document.addEventListener('click', (ev) => {
  if (!ev.target.closest('#stalk-ctx-menu')) hideBlockContextMenu();
});
document.addEventListener('keydown', (ev) => {
  if (ev.key === 'Escape') {
    hideBlockContextMenu();
    if (!document.getElementById('stalk-block-inspector')?.classList.contains('hidden'))
      closeBlockInspector();
  }
});

let stalkingProject = null;

async function loadStalkingView() {
  const targets = (await api.get('/api/targets')).filter(isVisibleTarget);
  const sel = document.getElementById('stalking-project');
  const prev = sel.value || stalkingProject;
  sel.innerHTML = targets.map((t) => `<option value="${t.name}">${t.name}</option>`).join('');
  if (prev && targets.some((t) => t.name === prev)) sel.value = prev;
  else if (targets.find((t) => t.name === 'vulnserver')) sel.value = 'vulnserver';
  stalkingProject = sel.value;
  await refreshStalkingWorkspace();
}

async function refreshStalkingWorkspace() {
  const project = document.getElementById('stalking-project').value;
  if (!project) return;
  stalkingProject = project;
  const ws = await api.get(`/api/stalking/${encodeURIComponent(project)}`);
  document.getElementById('stalking-hint').textContent = ws.workflowHint || '';

  const layers = ws.campaign?.layers || [];
  const layersEl = document.getElementById('stalking-layers');
  if (!layers.length) {
    layersEl.innerHTML = '<p class="empty">No layers yet — record a <strong>baseline</strong> after normal use under drcov (or import corpus edges).</p>';
  } else {
    layersEl.innerHTML = `<table><thead><tr>
      <th>Tag</th><th>Label</th><th>Blocks</th><th>When</th><th>Color</th><th></th>
    </tr></thead><tbody>
      ${layers.map((l) => `<tr>
        <td><code>${l.tag}</code></td>
        <td>${l.label}</td>
        <td><strong>${l.blockCount}</strong></td>
        <td>${new Date(l.createdAt).toLocaleString()}</td>
        <td><code>${l.colorHex}</code></td>
        <td><button type="button" class="btn" data-del-layer="${l.id}">Delete</button></td>
      </tr>`).join('')}
    </tbody></table>`;
    layersEl.querySelectorAll('[data-del-layer]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        await fetch(`/api/stalking/${encodeURIComponent(project)}/layers/${btn.dataset.delLayer}`, { method: 'DELETE' });
        await refreshStalkingWorkspace();
      });
    });
  }

  const compare = ws.campaign?.compare;
  const meta = document.getElementById('stalking-compare-meta');
  const deltasEl = document.getElementById('stalking-deltas');
  const blocksEl = document.getElementById('stalking-blocks');
  const graphEl = document.getElementById('stalking-block-graph');
  if (!compare || !compare.layerIds?.length) {
    meta.textContent = '';
    deltasEl.innerHTML = '';
    blocksEl.innerHTML = '';
    graphEl.innerHTML = '<p class="empty">Record at least one layer to see the block map.</p>';
  } else {
    meta.textContent = `— union ${compare.unionBlocks} · shared ${compare.sharedBlocks}`;
    deltasEl.innerHTML = `<table><thead><tr><th>Layer</th><th>Tag</th><th>Unique</th><th>New vs previous</th></tr></thead>
      <tbody>${(compare.deltas || []).map((d) => `<tr>
        <td><code>${d.layerId}</code></td><td>${d.tag}</td>
        <td>${d.uniqueBlocks}</td><td class="diff">+${d.newVsPrevious}</td>
      </tr>`).join('')}</tbody></table>`;

    const blocks = compare.blocks || [];
    graphEl.innerHTML = blocks.slice(0, 120).map((b) => `
      <span class="stalk-chip ${b.kind}" title="${b.module}:${b.address} (${b.firstLayerTag || ''})">
        <span class="addr">${b.address}</span>
        <span class="tag">${b.kind}${b.firstLayerTag ? ` · ${b.firstLayerTag}` : ''}</span>
      </span>`).join('') || '<p class="empty">No blocks in compare.</p>';

    blocksEl.innerHTML = `<table><thead><tr><th>Address</th><th>Module</th><th>Kind</th><th>First layer</th></tr></thead>
      <tbody>${blocks.slice(0, 80).map((b) => `<tr>
        <td><code>${b.address}</code></td><td>${b.module}</td>
        <td><span class="badge">${b.kind}</span></td>
        <td>${b.firstLayerTag || '—'}</td>
      </tr>`).join('')}</tbody></table>`;
  }

  const toolsEl = document.getElementById('stalking-tools');
  toolsEl.innerHTML = (ws.tools || []).map((t) => `
    <div class="tool-row" title="${t.commandHint || ''}">
      <div>
        <div class="name">${t.name}</div>
        <div class="desc">${t.description}</div>
      </div>
      <span class="tool-badge ${t.status}">${t.status}</span>
    </div>`).join('');

  // Drag-to-pan the Stalking bugs block chip map (scrollable for large unions)
  enableDragScroll(graphEl);

  await refreshStalkingMap(project);
  await refreshStalkingMissed(project);
}

async function refreshStalkingMap(project) {
  const meta = document.getElementById('stalking-map-meta');
  const hint = document.getElementById('stalking-map-hint');
  const ideasEl = document.getElementById('stalking-map-ideas');
  const hotEl = document.getElementById('stalking-map-hotspots');
  const impEl = document.getElementById('stalking-map-imports');
  const strEl = document.getElementById('stalking-map-strings');
  if (!meta || !hotEl) return;
  try {
    const map = await api.get(`/api/stalking/${encodeURIComponent(project)}/map?limit=40`);
    meta.textContent = `— ${map.format || '?'} · ${map.binaryPath ? map.binaryPath.split(/[/\\]/).pop() : 'no binary'}` +
      ` · hotspots ${(map.hotspots || []).length}`;
    hint.textContent = map.summary || '';

    const ideas = map.surfaceIdeas || [];
    ideasEl.innerHTML = ideas.length
      ? `<table><thead><tr><th>Pri</th><th>Idea</th><th>Detail</th></tr></thead><tbody>
          ${ideas.map((idea) => `<tr>
            <td><span class="badge pri-${idea.priority || 'low'}">${idea.priority || ''}</span></td>
            <td><strong>${escapeAttr(idea.title || '')}</strong></td>
            <td>${escapeAttr(idea.detail || '')}</td>
          </tr>`).join('')}
        </tbody></table>`
      : '<p class="empty">No surface ideas yet.</p>';

    const hotspots = map.hotspots || [];
    hotEl.innerHTML = hotspots.length
      ? `<table><thead><tr><th>Score</th><th>Kind</th><th>Address</th><th>Section</th><th>Nearby</th><th>Why</th></tr></thead><tbody>
          ${hotspots.map((h) => {
            const b = h.block || {};
            const near = [
              ...(h.nearbyImports || []).slice(0, 2),
              ...(h.nearbyStrings || []).slice(0, 2).map((s) => `"${s}"`),
            ].join(' · ') || '—';
            return `<tr>
              <td><strong>${h.boostedScore ?? b.priorityScore ?? ''}</strong></td>
              <td><span class="badge miss-${h.surfaceKind || ''}">${escapeAttr(h.surfaceKind || '')}</span></td>
              <td><code>${escapeAttr(b.module || '')}:${escapeAttr(b.address || '')}</code></td>
              <td>${escapeAttr(h.section || '—')}</td>
              <td class="hex">${escapeAttr(near)}</td>
              <td>${escapeAttr(b.whyMissed || '')}</td>
            </tr>`;
          }).join('')}
        </tbody></table>`
      : '<p class="empty">No hotspots — record baseline + fuzz layers, or import a BB inventory.</p>';

    const imports = map.interestingImports || [];
    impEl.innerHTML = imports.length
      ? `<table><thead><tr><th>Library</th><th>Function</th><th>Thunk</th></tr></thead><tbody>
          ${imports.slice(0, 24).map((i) => `<tr>
            <td>${escapeAttr(i.library || '')}</td>
            <td><code>${escapeAttr(i.function || '')}</code></td>
            <td class="hex">${escapeAttr(i.thunkRva || '—')}</td>
          </tr>`).join('')}
        </tbody></table>`
      : '<p class="empty">No interesting imports (resolve target.executable or pass binary).</p>';

    const strings = map.hotStrings || [];
    strEl.innerHTML = strings.length
      ? `<table><thead><tr><th>RVA</th><th>Section</th><th>String</th></tr></thead><tbody>
          ${strings.slice(0, 24).map((s) => `<tr>
            <td><code>${escapeAttr(s.rva || '')}</code></td>
            <td>${escapeAttr(s.section || '')}</td>
            <td>${escapeAttr(s.text || '')}</td>
          </tr>`).join('')}
        </tbody></table>`
      : '<p class="empty">No hot strings extracted yet.</p>';
  } catch (err) {
    meta.textContent = '';
    hint.textContent = err.message || 'Failed to load stalk map';
    ideasEl.innerHTML = '';
    hotEl.innerHTML = `<p class="empty">${escapeAttr(err.message || 'error')}</p>`;
    impEl.innerHTML = '';
    strEl.innerHTML = '';
  }
}

async function refreshStalkingMissed(project) {
  const meta = document.getElementById('stalking-missed-meta');
  const hint = document.getElementById('stalking-missed-hint');
  const catsEl = document.getElementById('stalking-missed-categories');
  const ideasEl = document.getElementById('stalking-missed-ideas');
  const blocksEl = document.getElementById('stalking-missed-blocks');
  if (!meta || !blocksEl) return;
  try {
    const report = await api.get(`/api/stalking/${encodeURIComponent(project)}/missed?limit=60`);
    meta.textContent = `— ${report.mode} · missed ${report.missedCount} · hit ${report.hitCount}` +
      (report.inventoryCount ? ` · inventory ${report.inventoryCount}` : '');
    hint.textContent = report.workflowHint || report.summary || '';
    catsEl.innerHTML = (report.categories || []).length
      ? (report.categories || []).map((c) => `
          <span class="stalk-missed-cat" title="${escapeAttr(c.description || '')}">
            <strong>${c.count}</strong> ${escapeAttr(c.label || c.id)}
          </span>`).join('')
      : '<span class="hex">No gap categories yet.</span>';

    const ideas = report.topIdeas || [];
    ideasEl.innerHTML = ideas.length
      ? `<table><thead><tr><th>Pri</th><th>Idea</th><th>Detail</th><th>Where</th></tr></thead><tbody>
          ${ideas.map((idea) => `<tr>
            <td><span class="badge pri-${idea.priority || 'low'}">${idea.priority || ''}</span></td>
            <td><strong>${escapeAttr(idea.title || '')}</strong></td>
            <td>${escapeAttr(idea.detail || '')}</td>
            <td class="hex">${escapeAttr(idea.uiHint || idea.cliHint || '—')}</td>
          </tr>`).join('')}
        </tbody></table>`
      : '<p class="empty">No fuzz ideas yet — record baseline + fuzzed layers.</p>';

    const blocks = report.blocks || [];
    blocksEl.innerHTML = blocks.length
      ? `<table><thead><tr><th>Category</th><th>Module</th><th>Address</th><th>Why missed</th><th>Best tip</th></tr></thead><tbody>
          ${blocks.map((b) => {
            const tip = (b.ideas && b.ideas[0]) ? b.ideas[0].title : '—';
            return `<tr>
              <td><span class="badge miss-${b.category || ''}">${escapeAttr(b.category || '')}</span></td>
              <td>${escapeAttr(b.module || '')}</td>
              <td><code>${escapeAttr(b.address || '')}</code></td>
              <td>${escapeAttr(b.whyMissed || '')}</td>
              <td>${escapeAttr(tip)}</td>
            </tr>`;
          }).join('')}
        </tbody></table>`
      : `<p class="empty">${escapeAttr(report.summary || 'No missed blocks to show.')}</p>`;
  } catch (err) {
    meta.textContent = '';
    hint.textContent = err.message || 'Failed to load missed blocks';
    catsEl.innerHTML = '';
    ideasEl.innerHTML = '';
    blocksEl.innerHTML = `<p class="empty">${escapeAttr(err.message || 'error')}</p>`;
  }
}

function enableDragScroll(el) {
  if (!el || el.dataset.dragScroll === '1') return;
  el.dataset.dragScroll = '1';
  let dragging = false;
  let x = 0;
  let y = 0;
  el.addEventListener('pointerdown', (ev) => {
    if (ev.button !== 0) return;
    dragging = true;
    x = ev.clientX;
    y = ev.clientY;
    el.classList.add('is-panning');
    try { el.setPointerCapture(ev.pointerId); } catch { /* ignore */ }
  });
  el.addEventListener('pointermove', (ev) => {
    if (!dragging) return;
    el.scrollLeft -= ev.clientX - x;
    el.scrollTop -= ev.clientY - y;
    x = ev.clientX;
    y = ev.clientY;
  });
  const end = () => {
    dragging = false;
    el.classList.remove('is-panning');
  };
  el.addEventListener('pointerup', end);
  el.addEventListener('pointercancel', end);
}

document.getElementById('stalking-project')?.addEventListener('change', () => refreshStalkingWorkspace().catch(() => {}));
document.getElementById('stalking-refresh')?.addEventListener('click', () => refreshStalkingWorkspace().catch(() => {}));

document.getElementById('stalking-add')?.addEventListener('click', async () => {
  const project = document.getElementById('stalking-project').value;
  const body = {
    project,
    tag: document.getElementById('stalking-tag').value,
    label: document.getElementById('stalking-label').value.trim() || null,
    drcovPath: document.getElementById('stalking-drcov').value.trim() || null,
    crashId: document.getElementById('stalking-crash').value.trim() || null,
  };
  try {
    await api.post('/api/stalking/layers', body);
    document.getElementById('stalking-label').value = '';
    document.getElementById('stalking-drcov').value = '';
    document.getElementById('stalking-crash').value = '';
    document.getElementById('stalking-export-result').textContent = `Layer recorded for ${project}`;
    await refreshStalkingWorkspace();
  } catch (err) {
    document.getElementById('stalking-export-result').textContent = err.message;
  }
});

document.getElementById('stalking-from-corpus')?.addEventListener('click', async () => {
  const project = document.getElementById('stalking-project').value;
  const tag = document.getElementById('stalking-tag').value || 'fuzzed';
  try {
    const layer = await api.post('/api/stalking/layers/from-corpus', { project, tag });
    document.getElementById('stalking-export-result').textContent =
      `Corpus layer: ${layer.tag} · ${layer.blockCount} blocks`;
    await refreshStalkingWorkspace();
  } catch (err) {
    document.getElementById('stalking-export-result').textContent = err.message;
  }
});

async function exportStalking(format) {
  const project = document.getElementById('stalking-project').value;
  const out = document.getElementById('stalking-export-result');
  try {
    const layers = await api.get(`/api/stalking/${encodeURIComponent(project)}/layers`);
    const result = await api.post('/api/stalking/export', {
      project,
      layerIds: layers.map((l) => l.id),
      format,
    });
    out.textContent = `Exported ${result.blockCount} blocks → ${result.outputPath}`;
  } catch (err) {
    out.textContent = err.message;
  }
}

document.getElementById('stalking-export-idc')?.addEventListener('click', () => exportStalking('idc'));
document.getElementById('stalking-export-ghidra')?.addEventListener('click', () => exportStalking('ghidra'));
document.getElementById('stalking-export-edges')?.addEventListener('click', () => exportStalking('edges'));

document.getElementById('stalking-inventory-import')?.addEventListener('click', async () => {
  const project = document.getElementById('stalking-project').value;
  const path = document.getElementById('stalking-inventory-path')?.value?.trim();
  const out = document.getElementById('stalking-export-result');
  if (!project || !path) {
    if (out) out.textContent = 'Set a lab path to a blocks.txt or drcov log first.';
    return;
  }
  try {
    const result = await api.post(`/api/stalking/${encodeURIComponent(project)}/inventory`, { path });
    if (out) out.textContent = `Inventory: ${result.blockCount} blocks → ${result.inventoryPath}`;
    await refreshStalkingMissed(project);
  } catch (err) {
    if (out) out.textContent = err.message;
  }
});

document.querySelectorAll('[data-stalk-action]').forEach((btn) => {
  btn.addEventListener('click', async () => {
    const action = btn.dataset.stalkAction;
    if (action === 'fuzz') switchView('fuzz');
    if (action === 'crashes') switchView('crashes');
    if (action === 'graph') switchView('graph');
    if (action === 'export' && stalkProject) {
      try {
        const crashes = await api.get(`/api/crashes?project=${encodeURIComponent(stalkProject)}`);
        if (!crashes.length) {
          alert('No crashes to export for this project.');
          return;
        }
        const bundle = await api.post(`/api/crashes/${crashes[0].id}/export`, {});
        alert(`Exported to ${bundle.exportPath}`);
      } catch (err) {
        alert(err.message);
      }
    }
  });
});

async function loadRoadmap() {
  const phases = await api.get('/api/roadmap');
  document.getElementById('roadmap-phases').innerHTML = phases.map((p) => `
    <div class="phase">
      <h3>Phase ${p.phase} — ${p.title}</h3>
      <div class="status">${p.status}</div>
      <ul>${p.items.map((i) => `
        <li><span class="${i.done ? 'done' : 'todo'}">${i.done ? '✓' : '○'}</span>
          ${i.title}${i.note ? ` <code>${i.note}</code>` : ''}</li>`).join('')}</ul>
    </div>`).join('');
}

async function loadLegs() {
  const legs = await api.get('/api/legs');
  document.getElementById('legs-list').innerHTML = legs.map((l) =>
    `<li><strong>${l.title}</strong> — ${l.summary}</li>`).join('');
}

/* —— Crashes investigate (NetWitness-style timeline → events → why) —— */
let crashState = {
  all: [],
  clusters: [],
  filtered: [],
  selectedId: null,
  selectedIndex: -1,
  bucketKey: null,
  classKey: null,
  clusterKey: null,
  uniqueOnly: true,
  pendingSelectId: null,
  detail: null,
};

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const CRASH_LIST_CAP = 200;

function crashSev(c) {
  return (c.severity || c.Severity || 'low').toLowerCase();
}

function crashClassKey(c) {
  return c.crashClass || c.exceptionHint || c.triageTag || 'unknown';
}

function crashClusterKey(c) {
  return c.clusterKey || c.ClusterKey || null;
}

function clusterMetaFor(crash) {
  const key = crashClusterKey(crash);
  if (key) {
    const hit = crashState.clusters.find((c) => c.clusterId === key);
    if (hit) return hit;
  }
  return crashState.clusters.find((c) => c.representativeId === crash.id)
    || crashState.clusters.find((c) => (c.crashClass || '') === (crash.crashClass || ''));
}

function clusterCountFor(crash) {
  return clusterMetaFor(crash)?.count
    || crashState.all.filter((x) => crashClusterKey(x) && crashClusterKey(x) === crashClusterKey(crash)).length
    || 1;
}

function scoreCrash(c) {
  const n = clusterCountFor(c);
  const sev = SEV_RANK[crashSev(c)] || 0;
  const unique = n <= 1 ? 18 : n <= 3 ? 12 : n <= 10 ? 6 : n <= 40 ? 2 : 0;
  const hasPc = c.faultAddress && !/no-pc|unk/i.test(c.faultAddress) ? 8 : 0;
  const hasDump = c.miniDumpPath ? 6 : 0;
  const ageHrs = Math.max(0, (Date.now() - new Date(c.observedAt).getTime()) / 3600000);
  const freshness = ageHrs < 1 ? 5 : ageHrs < 6 ? 3 : ageHrs < 24 ? 1 : 0;
  const mutatorBonus = /arith|havoc|expand|splice/i.test(c.mutator || '') ? 2 : 0;
  return sev * 12 + unique + hasPc + hasDump + freshness + mutatorBonus;
}

function shortMutator(m) {
  if (!m) return '—';
  const parts = m.split('/');
  return parts.length > 2 ? parts.slice(-2).join('/') : m;
}

function shortFault(c) {
  const f = c.faultAddress || c.exceptionHint || '';
  if (!f) return '—';
  if (/ACCESS_VIOLATION/i.test(f)) return 'AV';
  if (f.length > 22) return `${f.slice(0, 20)}…`;
  return f;
}

async function loadCrashMemoryLens(crashId) {
  const status = document.getElementById('crash-memory-status');
  const body = document.getElementById('crash-memory-body');
  const conf = document.getElementById('crash-memory-conf');
  if (!body) return;
  try {
    const m = await api.get(`/api/crashes/${crashId}/memory`);
    if (conf) conf.textContent = m.confidence ? `— ${m.confidence}` : '';
    if (status) {
      status.textContent = m.ok ? '' : (m.error || 'Lens unavailable');
      status.classList.toggle('hidden', !!m.ok && (m.summaryLines || []).length > 0);
    }
    const lines = (m.summaryLines || []).map((l) => `<p class="memory-summary-line">${escapeAttr(l)}</p>`).join('');
    const patterns = (m.patternHits || []).slice(0, 8).map((p) =>
      `<li><code>${escapeAttr(p.patternName)}</code> in ${escapeAttr(p.where)} — ${escapeAttr(p.hint)} <span class="hint">[${escapeAttr(p.confidence)}]</span></li>`).join('');
    const links = (m.linkHints || []).slice(0, 4).map((l) =>
      `<li>${escapeAttr(l.where)}: Flink <code>${escapeAttr(l.flink)}</code> Blink <code>${escapeAttr(l.blink)}</code> — ${escapeAttr(l.note)}</li>`).join('');
    const regions = (m.regions || []).slice(0, 10).map((r) =>
      `<tr><td><code>${escapeAttr(r.baseAddress)}</code></td><td>${escapeAttr(r.size)}</td><td>${escapeAttr(r.protect)}</td><td>${escapeAttr(r.kind)}</td><td>${escapeAttr(r.label || '')}</td></tr>`).join('');
    const hood = m.neighborhood
      ? `<p class="label">Neighborhood <code>${escapeAttr(m.neighborhood.baseAddress)}</code></p>
         <pre class="hex-preview">${escapeAttr(m.neighborhood.hexPreview || '')}</pre>
         ${(m.neighborhood.annotations || []).map((a) => `<p class="hint">${escapeAttr(a)}</p>`).join('')}`
      : '';
    const heap = (m.heapSummaryLines || []).length
      ? `<p class="label">Heap ${m.pageHeapLikely ? '(Page Heap likely) ' : ''}· ${escapeAttr(m.heapBackend || '')}</p>
         <ul class="memory-hit-list">${(m.heapSummaryLines || []).slice(0, 12).map((h) => `<li><code>${escapeAttr(h)}</code></li>`).join('')}</ul>`
      : '';
    body.innerHTML = `
      ${lines}
      ${patterns ? `<p class="label">Fill / UAF patterns</p><ul class="memory-hit-list">${patterns}</ul>` : ''}
      ${links ? `<p class="label">Link / unlink hints</p><ul class="memory-hit-list">${links}</ul>` : ''}
      ${heap}
      ${regions ? `<p class="label">Regions</p><table class="memory-region-table"><thead><tr><th>Base</th><th>Size</th><th>Prot</th><th>Kind</th><th>Label</th></tr></thead><tbody>${regions}</tbody></table>` : ''}
      ${hood}`;
  } catch (err) {
    if (status) status.textContent = err.message;
    body.innerHTML = '';
  }
}

function renderCrashDetail(detail, title) {
  const box = document.getElementById('crash-detail');
  const metaEl = document.getElementById('crash-invest-meta');
  if (!box) return;
  box.classList.remove('hidden');
  crashState.detail = detail;
  const s = detail.sidecar;
  const a = detail.analysis;
  const t = detail.triage;
  const regs = a?.registers;
  const why = t?.exceptionHint
    || s?.exceptionHint
    || detail.summary.exceptionHint
    || (detail.summary.targetExitCode ? `exit ${detail.summary.targetExitCode}` : 'unknown — open dump / analyze');
  const dump = detail.summary.miniDumpPath || a?.dumpPath || '';
  const windbgCmd = dump ? `windbg -z "${dump}"` : '';
  const procdumpCmd = dump
    ? `procdump -ma -e -accepteula -x dumps\\ "${dump}"`
    : 'procdump -ma -e -accepteula -x dumps\\ <target.exe>';
  const sev = (t?.severity || detail.summary.severity || 'low').toLowerCase();
  const cluster = clusterMetaFor(detail.summary);
  const clusterN = cluster?.count || clusterCountFor(detail.summary);
  const score = scoreCrash(detail.summary);
  if (metaEl) {
    metaEl.textContent = cluster
      ? `score ${score} · ${clusterN}× in cluster`
      : `score ${score}`;
  }

  box.innerHTML = `
    <div class="crash-why">
      <div class="crash-why-head">
        <span class="severity-${sev} crash-sev-pill">${sev}</span>
        <h3>${escapeAttr(title)}</h3>
        <span class="crash-score-badge" title="Triage score">★ ${score}</span>
      </div>
      <p class="crash-why-line">Why it crashed</p>
      <p class="crash-why-detail"><code>${escapeAttr(why)}</code>
        ${a?.faultAddress ? ` @ <code>${escapeAttr(a.faultAddress)}</code>` : ''}
        ${a?.faultModule ? ` in <code>${escapeAttr(a.faultModule)}</code>` : ''}
        ${detail.summary.faultAddress && !a?.faultAddress ? ` @ <code>${escapeAttr(detail.summary.faultAddress)}</code>` : ''}
      </p>
      ${t?.summary ? `<p class="hint">${escapeAttr(t.summary)}</p>` : ''}
      <div class="crash-why-actions">
        ${cluster ? `<button type="button" class="btn" id="crash-filter-cluster-btn">Browse ${clusterN}× cluster</button>` : ''}
        <button type="button" class="btn" id="crash-next-unique-inline">Next unique</button>
      </div>
    </div>
    <div class="crash-payload-block">
      <p class="label">Payload <span class="hex">${detail.inputLength} bytes</span></p>
      <pre class="ascii-preview">${escapeAttr(detail.asciiPreview || '(none)')}</pre>
      <p class="hex-preview">${escapeAttr(detail.hexPreview || '')}</p>
    </div>
    ${t ? `<div class="triage-box">
      <h4>Triage signals</h4>
      <p><code>${escapeAttr(t.class || '')}</code>${t.clusterKey ? ` · <code title="cluster key">${escapeAttr(t.clusterKey)}</code>` : ''}</p>
      ${t.ipLooksControlled ? '<p class="severity-critical">IP looks controlled / non-image</p>' : ''}
      ${t.stackLooksSmashed ? '<p class="severity-high">Stack smash signals</p>' : ''}
      ${t.patternDepthBytes != null ? `<p>Pattern depth: <code>offset ${t.patternDepthBytes}</code>${t.patternNote ? ` — ${escapeAttr(t.patternNote)}` : ''}</p>` : ''}
      ${!dump ? '<p class="hint">No minidump on this hit — severity may under-rank without PC.</p>' : ''}
    </div>` : ''}
    <dl class="crash-meta-dl">
      <dt>Project</dt><dd>${escapeAttr(detail.summary.project)}</dd>
      <dt>Iteration</dt><dd>#${detail.summary.iteration}</dd>
      <dt>Mutator</dt><dd><code>${escapeAttr(detail.summary.mutator)}</code></dd>
      <dt>When</dt><dd>${new Date(detail.summary.observedAt).toLocaleString()}</dd>
      <dt>Hash</dt><dd><code>${escapeAttr(detail.summary.inputHash)}</code></dd>
      ${s?.command ? `<dt>Command</dt><dd><code>${escapeAttr(s.command)}</code></dd>` : ''}
      ${s?.newEdgesAtCrash != null ? `<dt>Coverage</dt><dd>+${s.newEdgesAtCrash} new · ${s.totalEdgesAtCrash} total · <code>${escapeAttr(s.stalkBackend || '')}</code></dd>` : ''}
      <dt>Id</dt><dd><code>${detail.summary.id}</code></dd>
    </dl>
    ${regs ? `<div class="triage-box"><h4>Registers</h4>
      <div class="reg-grid">
        <div><span>RIP</span> <code>${regs.rip || '—'}</code></div>
        <div><span>RSP</span> <code>${regs.rsp || '—'}</code></div>
        <div><span>RBP</span> <code>${regs.rbp || '—'}</code></div>
        <div><span>RAX</span> <code>${regs.rax || '—'}</code></div>
        <div><span>RBX</span> <code>${regs.rbx || '—'}</code></div>
        <div><span>RCX</span> <code>${regs.rcx || '—'}</code></div>
        <div><span>RDX</span> <code>${regs.rdx || '—'}</code></div>
      </div></div>` : ''}
    <div class="triage-box" id="crash-memory-box">
      <h4>Memory lens <span class="hint-inline" id="crash-memory-conf"></span></h4>
      <p class="hint" id="crash-memory-status">Loading…</p>
      <div id="crash-memory-body"></div>
    </div>
    <div class="triage-box crash-triage-panel" id="crash-rop-box">
      <h4>Crash triage <span class="hint-inline">offset → stack map → gadgets → debugger</span></h4>
      <p class="hint crash-triage-lead" id="crash-rop-status">
        One walk: find CONTROL, map stack slots, learn badchars, sketch gadgets, export WinDbg/GDB notes.
        Outputs are citations and walk JSON — not exploit payloads.
      </p>
      <ol class="crash-triage-steps hint" aria-label="Triage flow">
        <li>CONTROL @ offset</li>
        <li>Stack map</li>
        <li>Badchars + ROP sketch</li>
        <li>Debugger walk</li>
      </ol>
      <div id="crash-rop-body" class="hint crash-triage-body"></div>
      <div class="crash-triage-primary">
        <label class="hint" for="crash-rop-goal">Sketch goal
          <select id="crash-rop-goal" title="auto picks from NX / PIE / canary">
            <option value="auto" selected>auto (tier-aware)</option>
            <option value="control">control</option>
            <option value="pivot">pivot</option>
            <option value="write">write</option>
            <option value="leak">leak</option>
            <option value="canary">canary</option>
          </select>
        </label>
        <label class="hint" for="crash-rop-badchars">Badchars
          <input type="text" id="crash-rop-badchars" size="18" placeholder="\x00\x0a (auto)" />
        </label>
        <button type="button" class="btn primary" id="crash-scream-walk-btn">Run triage walk</button>
      </div>
      <details class="crash-triage-more">
        <summary>Step tools <span class="hint-inline">stack · gadgets · debugger · ladder</span></summary>
        <div class="btn-row wrap crash-triage-more-row">
          <label class="hint" for="crash-rop-need">Need
            <input type="text" id="crash-rop-need" value="ret" size="10" placeholder="pop-rdi / pivot" />
          </label>
          <button type="button" class="btn" id="crash-stack-lens-btn">Stack map</button>
          <button type="button" class="btn" id="crash-rop-sketch-btn">ROP sketch</button>
          <button type="button" class="btn" id="crash-rop-search-btn">Search gadgets</button>
          <button type="button" class="btn" id="crash-rop-badchars-btn">Learn badchars</button>
          <button type="button" class="btn" id="crash-windbg-walk-btn">WinDbg walk</button>
          <button type="button" class="btn" id="crash-gdb-walk-btn">GDB walk</button>
          <button type="button" class="btn" id="crash-ladder-btn">Mitigation ladder</button>
        </div>
      </details>
    </div>
    <p class="hint crash-path"><code>${escapeAttr(detail.summary.inputPath)}</code></p>
    <div class="btn-row tool-cmds wrap">
      <button type="button" class="btn primary" id="export-crash-btn">Export triage</button>
      <button type="button" class="btn" id="stalk-layer-crash-btn">Stalk layer</button>
      ${dump ? `<button type="button" class="btn" id="open-windbg-preview-btn">WinDbg Preview</button>` : ''}
      ${dump ? `<button type="button" class="btn" id="open-windbg-btn">WinDbg</button>` : ''}
      ${windbgCmd ? `<button type="button" class="btn" id="copy-windbg-btn">Copy WinDbg</button>` : ''}
      <button type="button" class="btn" id="copy-procdump-btn">Copy ProcDump</button>
    </div>
    <p id="export-result" class="empty"></p>`;

  loadCrashMemoryLens(detail.summary.id).catch(() => {});
  loadCrashRopSidecars(detail.summary.id).catch(() => {});

  async function loadCrashRopSidecars(id) {
    const status = document.getElementById('crash-rop-status');
    const body = document.getElementById('crash-rop-body');
    const badInput = document.getElementById('crash-rop-badchars');
    try {
      const side = await api.get(`/api/crashes/${id}/rop-sidecars`);
      if (!side) return;
      if (status) status.textContent = side.summaryLine || 'Triage artifacts loaded';
      if (badInput && side.badChars?.badCharsHex) badInput.value = side.badChars.badCharsHex;
      if (!body) return;
      const parts = [];
      const stepsEl = document.querySelector('#crash-rop-box .crash-triage-steps');
      if (stepsEl && (side.screamWalk || side.stackLens || side.sketch || side.walkPath)) {
        stepsEl.classList.add('is-done-hint');
      }
      if (side.screamWalk) {
        const sw = side.screamWalk;
        parts.push(`<p class="hint">Triage walk · goal <code>${escapeAttr(sw.goalResolved || sw.goal || 'auto')}</code>` +
          (sw.controlledOffset != null
            ? ` · CONTROL <code>${escapeAttr(sw.controlledRegister || 'IP')}</code> @ ${sw.controlledOffset}`
            : '') +
          (sw.mitigationTier ? ` · ${escapeAttr(sw.mitigationTier)}` : '') +
          `</p>`);
        const swSteps = sw.steps || [];
        if (swSteps.length) {
          parts.push(`<ol class="crash-triage-result">${swSteps.map((s) =>
            `<li><strong>${escapeAttr(s.status || '')}</strong> ${escapeAttr(s.title || '')}` +
            (s.detail ? `<div class="hint">${escapeAttr(s.detail)}</div>` : '') +
            `</li>`).join('')}</ol>`);
        }
      }
      if (side.stackLens) {
        const lens = side.stackLens;
        const pc = lens.primaryControl;
        parts.push(`<p class="hint">Stack Lens · <code>${escapeAttr(lens.source || '')}</code>` +
          (pc
            ? ` · CONTROL <code>${escapeAttr(pc.where || '')}</code>` +
              (pc.inputOffset != null ? ` @ ${pc.inputOffset}` : '')
            : '') +
          `</p>`);
        const words = (lens.words || []).slice(0, 12);
        if (words.length) {
          parts.push(`<pre class="hint">${words.map((w) => {
            const slot = w.offsetFromSp >= 0
              ? `${escapeAttr(lens.spRegister || 'SP')}+0x${Number(w.offsetFromSp).toString(16)}`
              : escapeAttr(w.addressHex || '');
            return `${slot}  ${escapeAttr(w.valueHex || '')}  ${escapeAttr(w.role || '')}` +
              (w.inputOffset != null ? ` @ ${w.inputOffset}` : '');
          }).join('\n')}</pre>`);
        }
      }
      if (side.walk?.controlledOffset != null && !side.screamWalk?.controlledOffset && !side.stackLens?.primaryControl) {
        parts.push(`<p class="hint">CONTROL <code>${escapeAttr(side.walk.controlledRegister || 'IP')}</code> @ ${side.walk.controlledOffset}</p>`);
      }
      if (side.badChars?.badCharsHex) {
        parts.push(`<p>Badchars: <code>${escapeAttr(side.badChars.badCharsHex)}</code></p>`);
      }
      const steps = side.sketch?.steps || [];
      if (steps.length) {
        parts.push(`<p class="hint">ROP sketch · ${escapeAttr(side.sketch?.goal || '')}</p>`);
        parts.push(`<ol>${steps.map((s) =>
          `<li><code>${escapeAttr(s.gadget?.address || '')}</code>${s.gadget?.symbol ? ' @' + escapeAttr(s.gadget.symbol) : ''}
           ${escapeAttr(s.gadget?.instruction || s.role)}
           <div class="hint">${escapeAttr(s.why || '')}</div></li>`).join('')}</ol>`);
      } else if (side.walkPath || side.ropPath || side.screamWalkPath) {
        parts.push(`<p class="hint">Artifacts: <code>${escapeAttr(side.screamWalkPath || side.walkPath || side.ropPath || '—')}</code></p>`);
      }
      if (side.gdbWalkPath || side.gdbWalk) {
        parts.push(`<p class="hint">GDB walk: <code>${escapeAttr(side.gdbWalkPath || '—')}</code></p>`);
      }
      if (side.ladderPath) {
        parts.push(`<p class="hint">Ladder: <code>${escapeAttr(side.ladderPath)}</code></p>`);
      }
      if (side.walk?.moduleCandidates?.length) {
        parts.push(`<p class="hint">Modules: ${side.walk.moduleCandidates.map((m) => escapeAttr(m.split(/[\\\\/]/).pop())).join(', ')}</p>`);
      }
      if (parts.length) body.innerHTML = parts.join('');
      else if (status) {
        status.textContent = side.summaryLine
          || 'No triage artifacts yet — run the triage walk to build CONTROL, stack map, sketch, and debugger notes.';
      }
    } catch {
      /* no sidecars yet */
    }
  }

  document.getElementById('crash-rop-sketch-btn')?.addEventListener('click', async () => {
    const status = document.getElementById('crash-rop-status');
    const body = document.getElementById('crash-rop-body');
    const out = document.getElementById('export-result');
    const goal = document.getElementById('crash-rop-goal')?.value || 'auto';
    const badCharsHex = (document.getElementById('crash-rop-badchars')?.value || '').trim() || null;
    try {
      if (status) status.textContent = 'Sketching…';
      const sketch = await api.post('/api/rop/from-crash', {
        crashId: detail.summary.id,
        goal,
        badCharsHex,
      });
      if (status) status.textContent = sketch.summaryLine || 'ROP sketch';
      if (body) {
        const steps = sketch.steps || [];
        const constraints = (sketch.constraints || []).map((c) =>
          `<li class="hint">${escapeAttr(c)}</li>`).join('');
        body.innerHTML = (constraints ? `<ul>${constraints}</ul>` : '') + (steps.length
          ? `<ol>${steps.map((s) =>
              `<li><code>${escapeAttr(s.gadget?.address || '')}</code>${s.gadget?.symbol ? ' @' + escapeAttr(s.gadget.symbol) : ''}
               ${escapeAttr(s.gadget?.instruction || s.role)}
               <div class="hint">${escapeAttr(s.why || '')}</div></li>`).join('')}</ol>`
          : `<p class="empty">${escapeAttr(sketch.error || 'No gadgets — ensure TargetDetail / module path exists')}</p>`);
      }
      if (out) out.textContent = sketch.outputPath ? `Wrote ${sketch.outputPath}` : (sketch.summaryLine || '');
    } catch (err) {
      if (status) status.textContent = 'ROP sketch failed';
      if (out) out.textContent = err.message;
    }
  });

  document.getElementById('crash-stack-lens-btn')?.addEventListener('click', async () => {
    const status = document.getElementById('crash-rop-status');
    const body = document.getElementById('crash-rop-body');
    const out = document.getElementById('export-result');
    try {
      if (status) status.textContent = 'Mapping stack…';
      const report = await api.post('/api/stack/lens', {
        crashId: detail.summary.id,
        windowBytes: 128,
      });
      if (status) status.textContent = report.summaryLine || 'Stack map';
      if (body) {
        const pc = report.primaryControl;
        const words = report.words || [];
        body.innerHTML = `<p class="hint">Source <code>${escapeAttr(report.source || '')}</code>` +
          (pc
            ? ` · CONTROL <code>${escapeAttr(pc.where || '')}</code>` +
              (pc.inputOffset != null ? ` @ ${pc.inputOffset}` : '')
            : '') +
          `</p><pre class="hint">${words.slice(0, 16).map((w) => {
            const slot = w.offsetFromSp >= 0
              ? `${escapeAttr(report.spRegister || 'SP')}+0x${Number(w.offsetFromSp).toString(16)}`
              : escapeAttr(w.addressHex || '');
            return `${slot}  ${escapeAttr(w.valueHex || '')}  ${escapeAttr(w.role || '')}` +
              (w.inputOffset != null ? ` @ ${w.inputOffset}` : '');
          }).join('\n')}</pre>`;
      }
      if (out) out.textContent = report.outputPath ? `Wrote ${report.outputPath}` : (report.summaryLine || '');
      loadCrashRopSidecars(detail.summary.id).catch(() => {});
    } catch (err) {
      if (status) status.textContent = 'Stack map failed';
      if (out) out.textContent = err.message;
    }
  });

  document.getElementById('crash-scream-walk-btn')?.addEventListener('click', async () => {
    const status = document.getElementById('crash-rop-status');
    const body = document.getElementById('crash-rop-body');
    const out = document.getElementById('export-result');
    const goal = document.getElementById('crash-rop-goal')?.value || 'auto';
    const badCharsHex = (document.getElementById('crash-rop-badchars')?.value || '').trim() || null;
    try {
      if (status) status.textContent = 'Running triage walk…';
      const report = await api.post('/api/scream/walk', {
        crashId: detail.summary.id,
        goal,
        badCharsHex,
      });
      if (status) status.textContent = report.summaryLine || 'Triage walk complete';
      if (body) {
        const steps = report.steps || [];
        body.innerHTML = `<p class="hint">Goal <code>${escapeAttr(report.goalResolved || goal)}</code>` +
          (report.controlledOffset != null
            ? ` · CONTROL ${escapeAttr(report.controlledRegister || 'IP')} @ ${report.controlledOffset}`
            : '') +
          (report.mitigationTier ? ` · ${escapeAttr(report.mitigationTier)}` : '') +
          `</p><ol class="crash-triage-result">${steps.map((s) =>
            `<li><strong>${escapeAttr(s.status)}</strong> ${escapeAttr(s.title)}` +
            (s.detail ? `<div class="hint">${escapeAttr(s.detail)}</div>` : '') +
            (s.artifactPath ? `<div class="hint"><code>${escapeAttr(s.artifactPath)}</code></div>` : '') +
            `</li>`).join('')}</ol>`;
      }
      if (out) out.textContent = report.playbookPath ? `Wrote ${report.playbookPath}` : (report.summaryLine || '');
      loadCrashRopSidecars(detail.summary.id).catch(() => {});
    } catch (err) {
      if (status) status.textContent = 'Triage walk failed';
      if (out) out.textContent = err.message;
    }
  });

  document.getElementById('crash-gdb-walk-btn')?.addEventListener('click', async () => {
    const status = document.getElementById('crash-rop-status');
    const body = document.getElementById('crash-rop-body');
    const out = document.getElementById('export-result');
    try {
      if (status) status.textContent = 'Writing GDB walk…';
      const walk = await api.post('/api/gdb/walk', detail.summary.id);
      if (status) status.textContent = walk.summaryLine || 'GDB walk';
      if (body) {
        body.innerHTML = `<p>GDB walk: <code>${escapeAttr(walk.walkPath || '—')}</code></p>
          <pre class="hint">${(walk.scriptLines || []).slice(0, 8).map(escapeAttr).join('\n')}</pre>`;
      }
      if (out) out.textContent = walk.walkPath ? `Wrote ${walk.walkPath}` : (walk.summaryLine || '');
      loadCrashRopSidecars(detail.summary.id).catch(() => {});
    } catch (err) {
      if (status) status.textContent = 'GDB walk failed';
      if (out) out.textContent = err.message;
    }
  });

  document.getElementById('crash-ladder-btn')?.addEventListener('click', async () => {
    const status = document.getElementById('crash-rop-status');
    const body = document.getElementById('crash-rop-body');
    const out = document.getElementById('export-result');
    try {
      if (status) status.textContent = 'Comparing ladder…';
      const report = await api.post('/api/ladder/diff', {
        crashId: detail.summary.id,
        project: detail.summary.project,
      });
      if (status) status.textContent = report.summaryLine || 'Ladder diff';
      if (body) {
        const tiers = report.tiers || [];
        body.innerHTML = `<table class="hint"><thead><tr><th>tier</th><th>NX</th><th>canary</th><th>PIE</th><th>goal</th><th>gadgets</th></tr></thead><tbody>` +
          tiers.map((t) => `<tr>
            <td>${escapeAttr(t.tier)}</td>
            <td>${t.exists ? (t.nx ? 'yes' : 'no') : '—'}</td>
            <td>${t.exists ? (t.canary ? 'yes' : 'no') : '—'}</td>
            <td>${t.exists ? (t.pie ? 'yes' : 'no') : '—'}</td>
            <td>${escapeAttr(t.sketchGoalHint || '')}</td>
            <td>${t.gadgetCount ?? (t.exists ? '?' : 'missing')}</td>
          </tr>`).join('') + `</tbody></table>
          <ul>${(report.findings || []).map((f) => `<li class="hint">${escapeAttr(f)}</li>`).join('')}</ul>`;
      }
      if (out) out.textContent = report.outputPath ? `Wrote ${report.outputPath}` : (report.summaryLine || '');
      loadCrashRopSidecars(detail.summary.id).catch(() => {});
    } catch (err) {
      if (status) status.textContent = 'Ladder diff failed';
      if (out) out.textContent = err.message;
    }
  });

  document.getElementById('crash-rop-search-btn')?.addEventListener('click', async () => {
    const status = document.getElementById('crash-rop-status');
    const body = document.getElementById('crash-rop-body');
    const out = document.getElementById('export-result');
    const need = (document.getElementById('crash-rop-need')?.value || 'ret').trim() || 'ret';
    const badCharsHex = (document.getElementById('crash-rop-badchars')?.value || '').trim() || null;
    try {
      if (status) status.textContent = 'Searching…';
      const report = await api.post('/api/rop/search', {
        crashId: detail.summary.id,
        need,
        badCharsHex,
        limit: 24,
      });
      if (status) status.textContent = report.summaryLine || 'ROP search';
      if (body) {
        const hits = report.hits || [];
        body.innerHTML = hits.length
          ? `<ol>${hits.map((g) =>
              `<li><code>${escapeAttr(g.address || '')}</code> [${escapeAttr(g.kind || '')}] ${escapeAttr(g.instruction || '')}</li>`
            ).join('')}</ol>`
          : `<p class="empty">No hits for ${escapeAttr(need)}</p>`;
      }
      if (out) out.textContent = report.summaryLine || '';
    } catch (err) {
      if (status) status.textContent = 'ROP search failed';
      if (out) out.textContent = err.message;
    }
  });

  document.getElementById('crash-rop-badchars-btn')?.addEventListener('click', async () => {
    const status = document.getElementById('crash-rop-status');
    const body = document.getElementById('crash-rop-body');
    const out = document.getElementById('export-result');
    const badInput = document.getElementById('crash-rop-badchars');
    try {
      if (status) status.textContent = 'Learning badchars…';
      const report = await api.post('/api/rop/badchars', { crashId: detail.summary.id });
      if (status) status.textContent = report.summaryLine || 'Badchars';
      if (badInput && report.badCharsHex) badInput.value = report.badCharsHex;
      if (body) {
        const reasons = report.reasons || [];
        body.innerHTML = `<p><code>${escapeAttr(report.badCharsHex || '')}</code></p>
          <ul>${reasons.map((r) => `<li class="hint">${escapeAttr(r)}</li>`).join('')}</ul>`;
      }
      if (out) out.textContent = report.outputPath ? `Wrote ${report.outputPath}` : (report.summaryLine || '');
    } catch (err) {
      if (status) status.textContent = 'Badchar learn failed';
      if (out) out.textContent = err.message;
    }
  });

  document.getElementById('crash-windbg-walk-btn')?.addEventListener('click', async () => {
    const status = document.getElementById('crash-rop-status');
    const body = document.getElementById('crash-rop-body');
    const out = document.getElementById('export-result');
    try {
      if (status) status.textContent = 'Writing walk…';
      const walk = await api.post('/api/windbg/walk', detail.summary.id);
      if (status) status.textContent = walk.summaryLine || 'WinDbg walk';
      if (body) {
        body.innerHTML = `<p>Walk: <code>${escapeAttr(walk.walkPath || '—')}</code></p>
          ${walk.exceptionHint ? `<p class="hint">Exception: ${escapeAttr(walk.exceptionHint)}</p>` : ''}
          <pre class="hint">${(walk.scriptLines || []).slice(0, 8).map(escapeAttr).join('\n')}</pre>`;
      }
      if (out) out.textContent = walk.walkPath ? `Wrote ${walk.walkPath}` : (walk.summaryLine || '');
      loadCrashRopSidecars(detail.summary.id).catch(() => {});
    } catch (err) {
      if (status) status.textContent = 'Walk failed';
      if (out) out.textContent = err.message;
    }
  });

  document.getElementById('crash-filter-cluster-btn')?.addEventListener('click', () => {
    const key = t?.clusterKey || crashClusterKey(detail.summary) || cluster?.clusterId;
    if (!key) return;
    crashState.clusterKey = key;
    crashState.uniqueOnly = false;
    const uniq = document.getElementById('crash-unique-only');
    if (uniq) uniq.checked = false;
    paintCrashInvestigate();
  });
  document.getElementById('crash-next-unique-inline')?.addEventListener('click', () => selectNextUnique());
  document.getElementById('export-crash-btn')?.addEventListener('click', async () => {
    try {
      const bundle = await api.post(`/api/crashes/${detail.summary.id}/export`, {});
      document.getElementById('export-result').textContent = `Exported to ${bundle.exportPath}`;
    } catch (err) {
      document.getElementById('export-result').textContent = err.message;
    }
  });
  document.getElementById('stalk-layer-crash-btn')?.addEventListener('click', async () => {
    try {
      const layer = await api.post('/api/stalking/layers/from-crash', {
        crashId: detail.summary.id,
        tag: 'crash',
      });
      document.getElementById('export-result').textContent =
        `Stalk layer recorded: ${layer.tag} (${layer.blockCount} blocks) — open Stalking bugs`;
    } catch (err) {
      document.getElementById('export-result').textContent = err.message;
    }
  });
  document.getElementById('copy-windbg-btn')?.addEventListener('click', async () => {
    await navigator.clipboard.writeText(windbgCmd);
    document.getElementById('export-result').textContent = `Copied: ${windbgCmd}`;
  });
  document.getElementById('copy-procdump-btn')?.addEventListener('click', async () => {
    await navigator.clipboard.writeText(procdumpCmd);
    document.getElementById('export-result').textContent = `Copied: ${procdumpCmd}`;
  });
  document.getElementById('open-windbg-preview-btn')?.addEventListener('click', async () => {
    try {
      const r = await api.post('/api/debug/open', { crashId: detail.summary.id, kind: 'windbg-preview' });
      document.getElementById('export-result').textContent = r.message || 'Launched WinDbg Preview';
    } catch (err) {
      document.getElementById('export-result').textContent = err.message;
    }
  });
  document.getElementById('open-windbg-btn')?.addEventListener('click', async () => {
    try {
      const r = await api.post('/api/debug/open', { crashId: detail.summary.id, kind: 'windbg' });
      document.getElementById('export-result').textContent = r.message || 'Launched WinDbg';
    } catch (err) {
      document.getElementById('export-result').textContent = err.message;
    }
  });
}

function applyCrashFilters() {
  const sev = document.getElementById('crash-sev-filter')?.value || '';
  const sort = document.getElementById('crash-sort')?.value || 'best';
  crashState.uniqueOnly = !!document.getElementById('crash-unique-only')?.checked;
  let list = [...crashState.all];
  if (sev) list = list.filter((c) => crashSev(c) === sev);
  if (crashState.bucketKey != null) {
    list = list.filter((c) => timelineBucketKey(c) === crashState.bucketKey);
  }
  if (crashState.classKey) {
    list = list.filter((c) => crashClassKey(c) === crashState.classKey);
  }
  if (crashState.clusterKey) {
    list = list.filter((c) => {
      const key = crashClusterKey(c);
      if (key) return key === crashState.clusterKey;
      const meta = clusterMetaFor(c);
      return meta?.clusterId === crashState.clusterKey;
    });
  }
  if (crashState.uniqueOnly) {
    const seen = new Set();
    const reps = [];
    // Prefer newest high-score hit per cluster
    const ranked = [...list].sort((a, b) => scoreCrash(b) - scoreCrash(a)
      || new Date(b.observedAt) - new Date(a.observedAt));
    for (const c of ranked) {
      const key = crashClusterKey(c)
        || clusterMetaFor(c)?.clusterId
        || `${c.project}:${crashClassKey(c)}:${c.faultAddress || 'na'}`;
      if (seen.has(key)) continue;
      seen.add(key);
      reps.push(c);
    }
    list = reps;
  }
  if (sort === 'newest') {
    list.sort((a, b) => new Date(b.observedAt) - new Date(a.observedAt));
  } else if (sort === 'oldest') {
    list.sort((a, b) => new Date(a.observedAt) - new Date(b.observedAt));
  } else if (sort === 'cluster') {
    list.sort((a, b) => clusterCountFor(b) - clusterCountFor(a) || scoreCrash(b) - scoreCrash(a));
  } else {
    list.sort((a, b) => scoreCrash(b) - scoreCrash(a)
      || new Date(b.observedAt) - new Date(a.observedAt));
  }
  crashState.filtered = list;
}

function timelineBucketKey(c) {
  const d = new Date(c.observedAt);
  const m = Math.floor(d.getMinutes() / 15) * 15;
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}-${d.getHours()}-${m}`;
}

function parseBucketKey(key) {
  const [y, mo, d, h, m] = key.split('-').map(Number);
  return new Date(y, mo, d, h, m);
}

function formatBucketLabel(key) {
  return parseBucketKey(key).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

function nextBucketKey(key) {
  const dt = parseBucketKey(key);
  dt.setMinutes(dt.getMinutes() + 15);
  return `${dt.getFullYear()}-${dt.getMonth()}-${dt.getDate()}-${dt.getHours()}-${dt.getMinutes()}`;
}

function renderActiveCrashFilters() {
  const el = document.getElementById('crash-active-filters');
  if (!el) return;
  const pills = [];
  if (crashState.bucketKey) {
    pills.push({
      id: 'bucket',
      label: `Time: ${formatBucketLabel(crashState.bucketKey)}`,
    });
  }
  if (crashState.classKey) {
    pills.push({ id: 'class', label: `Class: ${crashState.classKey}` });
  }
  if (crashState.clusterKey) {
    const meta = crashState.clusters.find((c) => c.clusterId === crashState.clusterKey);
    pills.push({
      id: 'cluster',
      label: `Cluster: ${meta?.crashClass || 'fault'} ×${meta?.count || '?'}`,
    });
  }
  if (crashState.uniqueOnly) {
    pills.push({ id: 'unique', label: 'Unique only', sticky: true });
  }
  if (!pills.length) {
    el.innerHTML = '';
    el.classList.add('empty-filters');
    return;
  }
  el.classList.remove('empty-filters');
  el.innerHTML = pills.map((p) =>
    `<button type="button" class="crash-filter-pill ${p.sticky ? 'sticky' : ''}" data-clear="${p.id}">
      ${escapeAttr(p.label)}${p.sticky ? '' : ' ×'}
    </button>`).join('');
  el.querySelectorAll('.crash-filter-pill').forEach((btn) => {
    btn.addEventListener('click', () => {
      const id = btn.dataset.clear;
      if (id === 'bucket') crashState.bucketKey = null;
      if (id === 'class') crashState.classKey = null;
      if (id === 'cluster') crashState.clusterKey = null;
      if (id === 'unique') {
        crashState.uniqueOnly = false;
        const uniq = document.getElementById('crash-unique-only');
        if (uniq) uniq.checked = false;
      }
      paintCrashInvestigate();
    });
  });
}

function renderCrashTimeline() {
  const el = document.getElementById('crash-timeline');
  const axis = document.getElementById('crash-timeline-axis');
  const hint = document.getElementById('crash-timeline-hint');
  if (!el) return;
  const source = crashState.all;
  if (!source.length) {
    el.innerHTML = '<p class="empty">No crashes yet — run a campaign from the Fuzz tab.</p>';
    if (axis) axis.textContent = '';
    return;
  }
  const buckets = new Map();
  for (const c of source) {
    const k = timelineBucketKey(c);
    if (!buckets.has(k)) buckets.set(k, { key: k, items: [], maxSev: 0 });
    const b = buckets.get(k);
    b.items.push(c);
    b.maxSev = Math.max(b.maxSev, SEV_RANK[crashSev(c)] || 0);
  }
  const keys = [...buckets.keys()].sort((a, b) => a.localeCompare(b));
  // Fill gaps so the wire looks continuous
  const filled = [];
  if (keys.length) {
    let cur = keys[0];
    const end = keys[keys.length - 1];
    let guard = 0;
    while (cur.localeCompare(end) <= 0 && guard < 400) {
      filled.push(buckets.get(cur) || { key: cur, items: [], maxSev: 0, empty: true });
      if (cur === end) break;
      cur = nextBucketKey(cur);
      guard += 1;
    }
  }
  const maxCount = Math.max(...filled.map((b) => b.items.length), 1);
  el.innerHTML = filled.map((b) => {
    // sqrt scale so a 155-spike doesn't flatten the rest
    const ratio = b.items.length ? Math.sqrt(b.items.length / maxCount) : 0;
    const h = b.items.length ? Math.max(10, Math.round(ratio * 100)) : 3;
    const sevClass = !b.items.length ? 'empty'
      : b.maxSev >= 4 ? 'critical' : b.maxSev >= 3 ? 'high' : b.maxSev >= 2 ? 'medium' : 'low';
    const active = crashState.bucketKey === b.key ? 'active' : '';
    const label = formatBucketLabel(b.key);
    return `<button type="button" class="crash-bar ${sevClass} ${active}" data-bucket="${b.key}"
      style="height:${h}%" title="${label} — ${b.items.length} crash(es)" role="option"
      ${b.items.length ? '' : 'disabled'}>
      ${b.items.length >= 8 ? `<span class="crash-bar-count">${b.items.length}</span>` : ''}
    </button>`;
  }).join('');
  if (axis) {
    axis.textContent = keys.length
      ? `${formatBucketLabel(keys[0])}  →  ${formatBucketLabel(keys[keys.length - 1])} · 15m buckets`
      : '';
  }
  if (hint) {
    hint.textContent = crashState.bucketKey
      ? `brushed ${formatBucketLabel(crashState.bucketKey)}`
      : 'density · click to brush';
  }
  el.querySelectorAll('.crash-bar:not([disabled])').forEach((btn) => {
    btn.addEventListener('click', () => {
      const key = btn.dataset.bucket;
      crashState.bucketKey = crashState.bucketKey === key ? null : key;
      paintCrashInvestigate();
    });
  });
}

function renderCrashClassBars() {
  const el = document.getElementById('crash-class-bars');
  if (!el) return;
  const counts = new Map();
  for (const c of crashState.all) {
    const k = crashClassKey(c);
    if (!counts.has(k)) counts.set(k, { key: k, n: 0, sev: 0, clusters: new Set() });
    const row = counts.get(k);
    row.n += 1;
    row.sev = Math.max(row.sev, SEV_RANK[crashSev(c)] || 0);
    const ck = crashClusterKey(c);
    if (ck) row.clusters.add(ck);
  }
  const rows = [...counts.values()].sort((a, b) => b.n - a.n || b.sev - a.sev).slice(0, 8);
  const max = Math.max(...rows.map((r) => r.n), 1);
  if (!rows.length) {
    el.innerHTML = '<p class="empty">—</p>';
    return;
  }
  el.innerHTML = rows.map((r) => {
    const pct = Math.round((r.n / max) * 100);
    const sev = r.sev >= 4 ? 'critical' : r.sev >= 3 ? 'high' : r.sev >= 2 ? 'medium' : 'low';
    const active = crashState.classKey === r.key ? 'active' : '';
    const uniq = r.clusters.size || '—';
    return `<button type="button" class="crash-class-row ${active}" data-class="${escapeAttr(r.key)}">
      <span class="crash-class-name" title="${escapeAttr(r.key)}">${escapeAttr(r.key)}</span>
      <span class="crash-class-track"><span class="crash-class-fill ${sev}" style="width:${pct}%"></span></span>
      <span class="crash-class-n" title="${r.n} hits · ${uniq} clusters">${r.n}</span>
    </button>`;
  }).join('');
  el.querySelectorAll('.crash-class-row').forEach((btn) => {
    btn.addEventListener('click', () => {
      const key = btn.dataset.class;
      crashState.classKey = crashState.classKey === key ? null : key;
      paintCrashInvestigate();
    });
  });
}

function renderCrashClusterChips() {
  const el = document.getElementById('crash-clusters');
  if (!el) return;
  if (!crashState.clusters.length) {
    el.innerHTML = '<span class="hint">No clusters yet — unique faults will group here.</span>';
    return;
  }
  const sorted = [...crashState.clusters].sort((a, b) =>
    (SEV_RANK[(b.severity || '').toLowerCase()] || 0) - (SEV_RANK[(a.severity || '').toLowerCase()] || 0) ||
    b.count - a.count);
  el.innerHTML = `<span class="hint">Clusters</span>` +
    sorted.slice(0, 14).map((c) => {
      const sev = (c.severity || 'low').toLowerCase();
      const active = crashState.clusterKey === c.clusterId ? 'active' : '';
      return `<button type="button" class="crash-chip severity-${sev} ${active}" data-cluster="${escapeAttr(c.clusterId)}"
        data-rep="${c.representativeId}"
        title="${escapeAttr(c.exceptionHint || c.faultAddress || c.clusterId)}">
        <strong>${c.count}×</strong> ${escapeAttr(c.crashClass || 'fault')} · ${sev}
      </button>`;
    }).join('');
  el.querySelectorAll('.crash-chip').forEach((btn) => {
    btn.addEventListener('click', () => {
      const key = btn.dataset.cluster;
      if (crashState.clusterKey === key) {
        crashState.clusterKey = null;
      } else {
        crashState.clusterKey = key;
        crashState.uniqueOnly = false;
        const uniq = document.getElementById('crash-unique-only');
        if (uniq) uniq.checked = false;
      }
      paintCrashInvestigate();
      if (crashState.clusterKey) selectCrashById(btn.dataset.rep);
    });
  });
}

function renderCrashEventList() {
  const el = document.getElementById('crashes-table');
  const nav = document.getElementById('crash-nav-label');
  const stats = document.getElementById('crash-stats');
  if (!el) return;
  const list = crashState.filtered;
  const clusterN = crashState.clusters.length;
  if (stats) {
    const crit = crashState.all.filter((c) => crashSev(c) === 'critical').length;
    const high = crashState.all.filter((c) => crashSev(c) === 'high').length;
    stats.innerHTML =
      `<strong>${crashState.all.length}</strong> · ` +
      `<span class="severity-critical">${crit} crit</span> · ` +
      `<span class="severity-high">${high} high</span> · ` +
      `<span title="fault clusters">${clusterN} clusters</span> · ` +
      `show <strong>${list.length}</strong>`;
  }
  if (nav) {
    nav.textContent = list.length
      ? `${Math.max(0, crashState.selectedIndex) + 1} / ${list.length}`
      : '0 / 0';
  }
  if (!list.length) {
    el.innerHTML = '<p class="empty">No events match — clear facets or turn off Unique only.</p>';
    return;
  }
  const shown = list.slice(0, CRASH_LIST_CAP);
  const more = list.length - shown.length;
  el.innerHTML = `<table class="crash-event-table"><thead><tr>
    <th>#</th><th>When</th><th>Sev</th><th>Class</th><th>×</th><th>Mutator</th><th>Fault</th><th>★</th>
  </tr></thead><tbody>${shown.map((c, i) => {
    const sel = c.id === crashState.selectedId ? 'selected' : '';
    const score = scoreCrash(c);
    const n = clusterCountFor(c);
    const when = new Date(c.observedAt);
    const whenStr = when.toLocaleString(undefined, {
      month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
    return `<tr class="clickable crash-event ${sel}" data-id="${c.id}" data-idx="${i}">
      <td class="crash-idx">${i + 1}</td>
      <td class="crash-when">${whenStr}</td>
      <td class="severity-${crashSev(c)}">${crashSev(c)}</td>
      <td><code>${escapeAttr(crashClassKey(c))}</code></td>
      <td class="crash-dup" title="cluster size">${n}</td>
      <td title="${escapeAttr(c.mutator)}"><code>${escapeAttr(shortMutator(c.mutator))}</code></td>
      <td title="${escapeAttr(c.faultAddress || c.exceptionHint || '')}"><code>${escapeAttr(shortFault(c))}</code></td>
      <td class="crash-score">${score}</td>
    </tr>`;
  }).join('')}</tbody></table>
  ${more > 0 ? `<p class="hint crash-list-more">${more} more not shown — brush timeline / Unique only / cluster filter to narrow.</p>` : ''}
  <p class="hint crash-keys">↑↓/j k navigate · <kbd>n</kbd> next unique · <kbd>u</kbd> toggle unique</p>`;

  el.querySelectorAll('tr.crash-event').forEach((row) => {
    row.addEventListener('click', () => selectCrashById(row.dataset.id));
  });
  el.querySelector('tr.selected')?.scrollIntoView({ block: 'nearest' });
}

async function selectCrashById(id) {
  if (!id) return;
  let idx = crashState.filtered.findIndex((c) => c.id === id);
  if (idx < 0 && crashState.all.some((c) => c.id === id)) {
    // Reveal the crash without wiping Unique only unless needed
    crashState.bucketKey = null;
    crashState.classKey = null;
    crashState.clusterKey = crashClusterKey(crashState.all.find((c) => c.id === id)) || crashState.clusterKey;
    applyCrashFilters();
    idx = crashState.filtered.findIndex((c) => c.id === id);
    if (idx < 0) {
      crashState.uniqueOnly = false;
      const uniq = document.getElementById('crash-unique-only');
      if (uniq) uniq.checked = false;
      applyCrashFilters();
      idx = crashState.filtered.findIndex((c) => c.id === id);
    }
    renderCrashTimeline();
    renderCrashClassBars();
    renderCrashClusterChips();
    renderActiveCrashFilters();
  }
  crashState.selectedId = id;
  crashState.selectedIndex = idx;
  renderCrashEventList();
  try {
    const detail = await api.get(`/api/crashes/${id}`);
    const c = detail.summary;
    renderCrashDetail(detail, `${c.project} · iter #${c.iteration}`);
  } catch (err) {
    const box = document.getElementById('crash-detail');
    if (box) box.innerHTML = `<p class="empty">${escapeAttr(err.message)}</p>`;
  }
}

function selectCrashOffset(delta) {
  const list = crashState.filtered;
  if (!list.length) return;
  let idx = crashState.selectedIndex;
  if (idx < 0) idx = 0;
  else idx = Math.min(list.length - 1, Math.max(0, idx + delta));
  selectCrashById(list[idx].id);
}

function selectNextUnique() {
  const list = crashState.filtered;
  if (!list.length) return;
  const start = Math.max(0, crashState.selectedIndex);
  const startKey = crashClusterKey(list[start])
    || clusterMetaFor(list[start])?.clusterId
    || crashClassKey(list[start]);
  for (let i = 1; i <= list.length; i += 1) {
    const idx = (start + i) % list.length;
    const key = crashClusterKey(list[idx])
      || clusterMetaFor(list[idx])?.clusterId
      || crashClassKey(list[idx]);
    if (key !== startKey || crashState.uniqueOnly) {
      selectCrashById(list[idx].id);
      return;
    }
  }
  selectCrashOffset(1);
}

function canisterFillPct(count, capacity) {
  // Progressive fill for the porthole liquid — mood art still carries the story.
  const n = Math.max(0, Number(count) || 0);
  if (n <= 0) return 0;
  const cap = Math.max(1, Number(capacity) || 24);
  // Ease toward capacity: 1 scream ≈ 18%, mid around half, asymptote ~92%.
  const t = Math.min(1, n / cap);
  return Math.round(18 + t * 74);
}

/**
 * Atmosphere thresholds (EIP seal still wins over everything):
 *   laughter  — 0 unique screams (great / not sinister)
 *   watching  — 1–2 unique
 *   toxic     — 3–7 unique, or any critical
 *   virulent  — ≥8 unique, or ≥3 critical (more toxic / sinister)
 *   eip       — classic EIP/RIP overwrite seal
 */
function scoreHarvestMood({ unique = 0, critical = 0, ipCount = 0 } = {}) {
  if (ipCount > 0) return 'eip';
  if (unique <= 0) return 'laughter';
  if (unique >= 8 || critical >= 3) return 'virulent';
  if (unique >= 3 || critical >= 1) return 'toxic';
  return 'watching';
}

function moodRank(mood) {
  return ({ laughter: 0, watching: 1, toxic: 2, virulent: 3, eip: 4 })[mood] || 0;
}

function canisterArtForSlot(slot) {
  const mood = slot.mood || scoreHarvestMood({
    unique: slot.count || 0,
    critical: slot.critical || 0,
    ipCount: slot.ipCount || 0,
  });
  if (mood === 'eip') return '/canisters/canister-eip.jpg';
  if (mood === 'virulent') return '/canisters/canister-full.jpg';
  if (mood === 'toxic') return '/canisters/canister-mid.jpg';
  if (mood === 'watching') return '/canisters/canister-low.jpg';
  return '/canisters/canister-empty.jpg';
}

function gaugeAngleForFill(pct, mood) {
  // Analog dial sweep: -110deg (idle) → +110deg (pegged red).
  if (mood === 'eip') return 110;
  const p = Math.max(0, Math.min(100, Number(pct) || 0));
  return Math.round(-110 + (p / 100) * 220);
}

function screamCaptionForMood(mood) {
  return ({
    laughter: 'laughter',
    watching: 'yelp',
    toxic: 'toxic scream',
    virulent: 'virulent scream',
    eip: 'EIP seal',
  })[mood] || 'scream';
}

function moodHue(mood, fallback) {
  if (mood === 'eip') return 8;
  if (mood === 'virulent') return 95; // sickly toxic green
  if (mood === 'toxic') return 78;
  if (mood === 'watching') return fallback != null ? fallback : 188;
  if (mood === 'laughter') return 48; // warm gold
  return fallback != null ? fallback : 188;
}

function pressureLabel(pct) {
  if (pct <= 0) return 'PRESSURE IDLE';
  if (pct < 25) return 'PRESSURE LOW';
  if (pct < 55) return 'PRESSURE BUILDING';
  if (pct < 85) return 'PRESSURE HIGH';
  return 'PRESSURE CRITICAL';
}

function crashIpControlled(c) {
  return !!(c?.ipLooksControlled || c?.IpLooksControlled);
}

function harvestIpControlCount(crashes) {
  let n = 0;
  for (const c of crashes || []) {
    if (crashIpControlled(c)) n += 1;
  }
  return n;
}

function harvestCriticalCount(crashes) {
  let n = 0;
  for (const c of crashes || []) {
    if (crashSev(c) === 'critical') n += 1;
  }
  return n;
}

function markHarvestProjectSeen(name) {
  if (!name) return;
  if (!harvestState.seenProjects) harvestState.seenProjects = new Set();
  const key = String(name);
  if (harvestState.seenProjects.has(key)) return;
  harvestState.seenProjects.add(key);
  try {
    localStorage.setItem('randfuzz.seenProjects', JSON.stringify([...harvestState.seenProjects]));
  } catch { /* ignore */ }
}

function loadSeenHarvestProjects() {
  try {
    const raw = localStorage.getItem('randfuzz.seenProjects');
    if (!raw) return;
    const list = JSON.parse(raw);
    if (!Array.isArray(list)) return;
    if (!harvestState.seenProjects) harvestState.seenProjects = new Set();
    for (const n of list) {
      if (n) harvestState.seenProjects.add(String(n));
    }
  } catch { /* ignore */ }
}

/** Live harvest snapshot — browser UI only (does not touch fuzz-process RAM). */
let harvestState = {
  all: [],
  lastUnique: 0,
  lastIpCount: 0,
  refreshTimer: null,
  prevFillById: {},
  mode: 'projects', // projects | severity
  liveProject: null,
  seenProjects: new Set(),
};

function harvestUniqueCount(crashes) {
  const keys = new Set();
  for (const c of crashes || [])
    keys.add(crashClusterKey(c) || c.id);
  return keys.size;
}

function crashProjectName(c) {
  return c.project || c.Project || 'unknown';
}

function projectCanisterHue(name) {
  let h = 2166136261;
  const s = String(name || '');
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  // Industrial amber / teal / steel — avoid purple defaults
  const hues = [22, 34, 48, 78, 152, 188, 204];
  return hues[Math.abs(h) % hues.length];
}

function flashScreamBottled(detail = '', { ipControlled = false } = {}) {
  if (document.documentElement.getAttribute('data-scream-canisters') === 'off') return;
  // EIP/RIP control is the special moment — always toast (even with animations off).
  // Ordinary bottled screams only toast when animations are enabled.
  if (!ipControlled && document.documentElement.getAttribute('data-scream-anim') !== 'on') return;
  let toast = document.getElementById('scream-bottled-toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'scream-bottled-toast';
    toast.className = 'scream-bottled-toast';
    toast.setAttribute('role', 'status');
    document.body.appendChild(toast);
  }
  toast.classList.toggle('eip-capture', !!ipControlled);
  toast.textContent = ipControlled
    ? (detail ? `EIP/RIP controlled — ${detail}` : 'EIP/RIP controlled — canister sealed')
    : (detail ? `Scream bottled — ${detail}` : 'Scream bottled');
  toast.classList.add('show');
  clearTimeout(toast._hide);
  toast._hide = setTimeout(() => toast.classList.remove('show', 'eip-capture'), ipControlled ? 5200 : 3200);
}

function buildHarvestSlots(all, { compact = false, mode = 'projects' } = {}) {
  if (mode === 'severity') {
    const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
    let ipHits = 0;
    for (const c of all) {
      const s = crashSev(c);
      if (bySev[s] != null) bySev[s] += 1;
      else bySev.low += 1;
      if (crashIpControlled(c)) ipHits += 1;
    }
    const unique = harvestUniqueCount(all);
    const mood = scoreHarvestMood({ unique, critical: bySev.critical, ipCount: ipHits });
    return [
      {
        id: 'harvest',
        label: compact ? 'All' : 'Harvest',
        count: unique,
        capacity: 40,
        project: '',
        sevFilter: '',
        cls: `harvest mood-${mood}${ipHits ? ' ip-controlled' : ''}`,
        title: ipHits
          ? `Unique screams · ${ipHits} with EIP/RIP control`
          : `Unique bottled screams · mood ${mood}`,
        ipControlled: ipHits > 0,
        ipCount: ipHits,
        critical: bySev.critical,
        mood,
        scream: screamCaptionForMood(mood),
      },
      ...['critical', 'high', 'medium', 'low'].map((sev) => {
        const count = bySev[sev];
        const sevMood = scoreHarvestMood({
          unique: count,
          critical: sev === 'critical' ? count : 0,
          ipCount: 0,
        });
        return {
          id: sev,
          label: compact && sev === 'critical' ? 'Crit' : (compact && sev === 'medium' ? 'Med' : sev[0].toUpperCase() + sev.slice(1)),
          count,
          capacity: sev === 'critical' ? 12 : sev === 'high' ? 20 : 30,
          project: '',
          sevFilter: sev,
          cls: `${sev} mood-${sevMood}`,
          title: `${sev} · ${screamCaptionForMood(sevMood)}`,
          ipControlled: false,
          ipCount: 0,
          critical: sev === 'critical' ? count : 0,
          mood: sevMood,
          scream: screamCaptionForMood(sevMood),
        };
      }),
    ];
  }

  // One canister per test/project (Target profile)
  const byProject = new Map();
  for (const c of all) {
    const p = crashProjectName(c);
    markHarvestProjectSeen(p);
    if (!byProject.has(p)) byProject.set(p, []);
    byProject.get(p).push(c);
  }

  if (harvestState.liveProject) markHarvestProjectSeen(harvestState.liveProject);

  // Clean / laughter canisters: fuzz targets we've seen that never screamed
  for (const name of harvestState.seenProjects || []) {
    if (!byProject.has(name)) byProject.set(name, []);
  }

  let names = [...byProject.keys()].sort((a, b) => {
    const listA = byProject.get(a) || [];
    const listB = byProject.get(b) || [];
    const moodA = scoreHarvestMood({
      unique: harvestUniqueCount(listA),
      critical: harvestCriticalCount(listA),
      ipCount: harvestIpControlCount(listA),
    });
    const moodB = scoreHarvestMood({
      unique: harvestUniqueCount(listB),
      critical: harvestCriticalCount(listB),
      ipCount: harvestIpControlCount(listB),
    });
    if (moodRank(moodB) !== moodRank(moodA)) return moodRank(moodB) - moodRank(moodA);
    const ua = harvestUniqueCount(listA);
    const ub = harvestUniqueCount(listB);
    if (ub !== ua) return ub - ua;
    return a.localeCompare(b);
  });

  if (harvestState.liveProject && !byProject.has(harvestState.liveProject)) {
    names = [harvestState.liveProject, ...names];
    byProject.set(harvestState.liveProject, []);
  }

  // Keep the live fuzz target first so its canister stays on-camera during campaigns.
  if (harvestState.liveProject && names.includes(harvestState.liveProject)) {
    names = [harvestState.liveProject, ...names.filter((n) => n !== harvestState.liveProject)];
  }

  if (compact) names = names.slice(0, 5);
  else names = names.slice(0, 12);

  if (!names.length) {
    return [{
      id: 'empty-slot',
      label: compact ? 'Idle' : 'Awaiting',
      count: 0,
      capacity: 20,
      project: '',
      sevFilter: '',
      cls: 'harvest mood-laughter',
      title: 'No tests bottled yet — laughter on the scare floor',
      ipControlled: false,
      ipCount: 0,
      critical: 0,
      mood: 'laughter',
      scream: 'laughter',
    }];
  }

  return names.map((name) => {
    const list = byProject.get(name) || [];
    const unique = harvestUniqueCount(list);
    const ipCount = harvestIpControlCount(list);
    const critical = harvestCriticalCount(list);
    const mood = scoreHarvestMood({ unique, critical, ipCount });
    const ipControlled = ipCount > 0;
    const live = harvestState.liveProject && name === harvestState.liveProject;
    const cls = [
      'harvest',
      `mood-${mood}`,
      live ? 'live' : '',
      ipControlled ? 'ip-controlled' : '',
    ].filter(Boolean).join(' ');
    return {
      id: `proj:${name}`,
      label: name.length > 14 ? `${name.slice(0, 12)}…` : name,
      count: unique,
      capacity: Math.max(8, compact ? 16 : 24),
      project: name,
      sevFilter: '',
      cls,
      title: ipControlled
        ? `${name} — EIP/RIP controlled (${ipCount}) · sealed`
        : `${name} — ${screamCaptionForMood(mood)} · ${unique} unique`,
      hue: moodHue(mood, projectCanisterHue(name)),
      live,
      ipControlled,
      ipCount,
      critical,
      mood,
      scream: screamCaptionForMood(mood),
    };
  });
}

function canisterFloatiesHtml(mood) {
  // Lightweight CSS scare / laughter sprites — browser-only, no fuzz RAM.
  if (mood === 'laughter') {
    return `<div class="canister-floaties laughter" aria-hidden="true">
      <span class="floatie smile" style="--t:0"></span>
      <span class="floatie ha" style="--t:1">ha</span>
      <span class="floatie smile" style="--t:2"></span>
    </div>`;
  }
  if (mood === 'watching') {
    return `<div class="canister-floaties watching" aria-hidden="true">
      <span class="floatie mote" style="--t:0"></span>
      <span class="floatie mote" style="--t:1"></span>
    </div>`;
  }
  if (mood === 'toxic' || mood === 'virulent' || mood === 'eip') {
    const n = mood === 'eip' ? 5 : mood === 'virulent' ? 4 : 3;
    const bits = [];
    for (let i = 0; i < n; i++) {
      bits.push(`<span class="floatie scare scare-${i % 3}" style="--t:${i}"></span>`);
    }
    if (mood === 'eip' || mood === 'virulent') {
      bits.push('<span class="floatie skull-haze" style="--t:2"></span>');
    }
    return `<div class="canister-floaties ${mood}" aria-hidden="true">${bits.join('')}</div>`;
  }
  return '';
}

function paintHarvestAmbience(root, floorMood, stats = {}) {
  let layer = root.querySelector('.scream-harvest-ambience');
  if (!layer) {
    layer = document.createElement('div');
    layer.className = 'scream-harvest-ambience';
    layer.setAttribute('aria-hidden', 'true');
    root.insertBefore(layer, root.firstChild);
  }
  const animOn = document.documentElement.getAttribute('data-scream-anim') === 'on';
  layer.dataset.mood = floorMood;
  layer.classList.toggle('anim', animOn);

  if (floorMood === 'laughter') {
    layer.innerHTML = `
      <span class="amb smile a0"></span><span class="amb ha a1">ha</span>
      <span class="amb smile a2"></span><span class="amb ha a3">ha</span>
      <span class="amb spark a4"></span>`;
    return;
  }
  if (floorMood === 'watching') {
    layer.innerHTML = `<span class="amb mote a0"></span><span class="amb mote a1"></span>`;
    return;
  }
  // Toxic / virulent / EIP — floating scares that spook humans
  const density = floorMood === 'eip' ? 7 : floorMood === 'virulent' ? 6 : 4;
  const parts = [];
  for (let i = 0; i < density; i++) {
    const kind = i % 4 === 0 ? 'door' : i % 4 === 1 ? 'human' : i % 4 === 2 ? 'eye' : 'wail';
    parts.push(`<span class="amb scare ${kind} a${i}" style="--i:${i}"></span>`);
  }
  if (stats.ipHits) parts.push('<span class="amb seal-flare"></span>');
  layer.innerHTML = parts.join('');
}

function animateCanisterFills(rack) {
  const buttons = [...rack.querySelectorAll('.scream-canister[data-slot]')];
  const animOn = document.documentElement.getAttribute('data-scream-anim') === 'on';
  if (!animOn) {
    for (const btn of buttons) {
      const id = btn.dataset.slot || '';
      const target = Number(btn.dataset.targetFill || btn.dataset.fill || 0);
      harvestState.prevFillById[id] = target;
      btn.style.setProperty('--fill', `${target}%`);
      btn.classList.remove('filling', 'pulse', 'just-bottled');
    }
    return;
  }
  for (const btn of buttons) {
    const id = btn.dataset.slot;
    const target = Number(btn.dataset.targetFill || 0);
    const from = harvestState.prevFillById[id] ?? 0;
    btn.style.setProperty('--fill', `${from}%`);
    // Double rAF so the browser commits the starting fill before transitioning.
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        btn.style.setProperty('--fill', `${target}%`);
        if (target > from) btn.classList.add('just-bottled');
      });
    });
    harvestState.prevFillById[id] = target;
  }
}

function renderScreamCanisters(opts = {}) {
  if (document.documentElement.getAttribute('data-scream-canisters') === 'off') {
    const rack = document.getElementById(opts.rackId || 'scream-canister-rack');
    if (rack) rack.innerHTML = '';
    const harvestRoot = document.querySelector('.scream-harvest');
    const amb = harvestRoot?.querySelector('.scream-harvest-ambience');
    if (amb) amb.innerHTML = '';
    return;
  }
  const rackId = opts.rackId || 'scream-canister-rack';
  const statusId = opts.statusId || 'scream-harvest-status';
  const pressureId = opts.pressureId || 'scream-harvest-pressure';
  const compact = !!opts.compact;
  const mode = opts.mode || harvestState.mode || 'projects';
  const rack = document.getElementById(rackId);
  const status = document.getElementById(statusId);
  const pressure = document.getElementById(pressureId);
  if (!rack) return;

  const all = opts.crashes || harvestState.all || crashState.all || [];
  const unique = harvestUniqueCount(all);
  const ipHits = harvestIpControlCount(all);
  const criticalHits = harvestCriticalCount(all);
  const slots = buildHarvestSlots(all, { compact, mode });
  const floorMood = slots.reduce(
    (best, s) => (moodRank(s.mood) > moodRank(best) ? s.mood : best),
    scoreHarvestMood({ unique, critical: criticalHits, ipCount: ipHits }),
  );

  if (!compact) {
    const harvestRoot = rack.closest('.scream-harvest');
    if (harvestRoot) {
      harvestRoot.dataset.floorMood = floorMood;
      paintHarvestAmbience(harvestRoot, floorMood, { unique, ipHits, critical: criticalHits });
    }
  }

  if (status) {
    const projects = new Set(slots.map((s) => s.project).filter(Boolean));
    if (!all.length && ![...harvestState.seenProjects || []].length) {
      status.textContent = compact
        ? 'Scare floor quiet — laughter waiting.'
        : 'Scare floor quiet — start a fuzz run; clean tests stay on laughter.';
    } else if (ipHits > 0) {
      status.textContent = `${slots.length} canister${slots.length === 1 ? '' : 's'} · ${ipHits} EIP seal · floor ${floorMood}`;
    } else {
      status.textContent = `${slots.length} canister${slots.length === 1 ? '' : 's'} · ${unique} unique · floor ${floorMood}`;
    }
  }
  if (pressure) {
    pressure.classList.remove('critical', 'eip-capture', 'laughter', 'toxic', 'virulent');
    if (floorMood === 'eip') {
      pressure.textContent = 'EIP CAPTURED';
      pressure.classList.add('critical', 'eip-capture');
      pressure.title = `${ipHits} EIP/RIP overwrite seal${ipHits === 1 ? '' : 's'}`;
    } else if (floorMood === 'virulent') {
      pressure.textContent = 'TOXIC FLOOR';
      pressure.classList.add('critical', 'virulent');
      pressure.title = '≥8 unique screams or ≥3 critical — virulent / sinister';
    } else if (floorMood === 'toxic') {
      pressure.textContent = 'TOXIC RISING';
      pressure.classList.add('toxic');
      pressure.title = '3–7 unique or any critical — toxic screams';
    } else if (floorMood === 'watching') {
      pressure.textContent = 'WATCHING';
      pressure.title = '1–2 unique screams — mild yelps';
    } else {
      pressure.textContent = 'LAUGHTER';
      pressure.classList.add('laughter');
      pressure.title = 'No screams bottled — scare floor stays great / not sinister';
    }
  }

  const modeEl = document.getElementById('scream-harvest-mode');
  if (modeEl && !compact) modeEl.value = mode;

  const rose = unique > harvestState.lastUnique;
  const ipRose = ipHits > harvestState.lastIpCount;
  const activeSev = document.getElementById('crash-sev-filter')?.value || '';
  const activeProject = document.getElementById('crash-filter')?.value || '';

  rack.innerHTML = slots.map((s) => {
    const mood = s.mood || 'watching';
    const moodFloor = mood === 'eip' ? 100
      : mood === 'virulent' ? 72
      : mood === 'toxic' ? 48
      : mood === 'watching' ? 28
      : 0;
    const progressive = canisterFillPct(s.count, s.capacity);
    const pct = mood === 'eip' ? 100 : Math.max(moodFloor, progressive);
    const art = canisterArtForSlot(s);
    const active = mode === 'severity'
      ? (!compact && s.sevFilter && activeSev === s.sevFilter ? 'active' : '')
      : (!compact && s.project && activeProject === s.project ? 'active' : '');
    const filling = pct > 0 ? 'filling' : '';
    const pulse = ((rose || ipRose) && (s.ipControlled || s.live || mood === 'virulent')) ? 'pulse' : '';
    const live = s.live ? 'is-live' : '';
    const hue = moodHue(mood, s.hue);
    const gauge = gaugeAngleForFill(pct, mood);
    const style = [
      `--fill: 0%`,
      `--gauge: ${gauge}deg`,
      `--canister-glow: hsl(${hue} 90% 48%)`,
      `--mood-accent: hsl(${hue} 85% 55%)`,
    ].join(';');
    const metaCount = s.ipControlled
      ? (compact ? `EIP×${s.ipCount || 1}` : `EIP ${s.ipCount || 1}`)
      : (mood === 'laughter' ? 'ha' : String(s.count));
    const critChip = (!compact && s.critical > 0 && !s.ipControlled)
      ? `<span class="scream-canister-crit" title="${s.critical} critical">${s.critical} crit</span>`
      : '';
    const footer = compact
      ? ''
      : `<div class="scream-canister-foot">
          <span class="scream-canister-pct mood-${mood}">${escapeAttr(s.scream || screamCaptionForMood(mood))}</span>
          ${critChip}
          <span class="scream-canister-fill-readout" title="Porthole fill">${pct}%</span>
        </div>`;
    const floaties = compact ? '' : canisterFloatiesHtml(mood);
    return `<button type="button" class="scream-canister ${s.cls} ${active} ${filling} ${pulse} ${live}" role="listitem"
      data-slot="${s.id}" data-target-fill="${pct}" data-sev="${s.sevFilter || ''}" data-project="${s.project || ''}"
      data-fill="${pct}" data-ip="${s.ipControlled ? '1' : '0'}" data-mood="${mood}" title="${escapeAttr(s.title)}" style="${style}">
      <div class="scream-canister-vessel">
        <img class="scream-canister-art" src="${art}" alt="" width="186" height="280" loading="lazy" decoding="async" />
        <div class="scream-canister-porthole" aria-hidden="true">
          <div class="scream-canister-liquid"></div>
        </div>
        <div class="scream-canister-gauge" aria-hidden="true" title="Harvest pressure">
          <span class="scream-canister-gauge-needle"></span>
        </div>
        <div class="scream-canister-vapor" aria-hidden="true"></div>
        ${floaties}
        ${s.ipControlled ? '<span class="scream-canister-eip-badge" title="Instruction pointer looks controlled">EIP</span>' : ''}
        ${mood === 'laughter' ? '<span class="scream-canister-laugh-badge" title="No screams — scare floor laughter">HA</span>' : ''}
        ${s.live ? '<span class="scream-canister-live-badge">LIVE</span>' : ''}
      </div>
      <div class="scream-canister-meta">
        <span class="scream-canister-label">${escapeAttr(s.label)}</span>
        <span class="scream-canister-count">${escapeAttr(metaCount)}</span>
      </div>
      ${footer}
    </button>`;
  }).join('');

  if (!all.length && !compact && mode === 'projects') {
    rack.insertAdjacentHTML('beforeend', `
      <div class="scream-canister-empty" role="status">
        <img src="/canisters/canister-empty.jpg" alt="" width="120" height="180" loading="lazy" decoding="async" />
        <p>Empty rack — clean tests laugh here; bottled screams turn the floor toxic.</p>
      </div>`);
  }

  animateCanisterFills(rack);

  rack.querySelectorAll('.scream-canister').forEach((btn) => {
    btn.addEventListener('click', () => {
      const sev = btn.dataset.sev || '';
      const project = btn.dataset.project || '';
      if (compact) {
        switchView('crashes');
        const projSel = document.getElementById('crash-filter');
        const sevSel = document.getElementById('crash-sev-filter');
        if (mode === 'projects' && projSel && project) {
          // Ensure option exists
          if (![...projSel.options].some((o) => o.value === project)) {
            const opt = document.createElement('option');
            opt.value = project;
            opt.textContent = project;
            projSel.appendChild(opt);
          }
          projSel.value = project;
        }
        if (mode === 'severity' && sevSel && sev) sevSel.value = sev;
        loadCrashes(document.getElementById('crash-filter')?.value || '').catch(() => {});
        return;
      }
      if (mode === 'projects') {
        const projSel = document.getElementById('crash-filter');
        if (!projSel) return;
        if (!project) {
          projSel.value = '';
        } else {
          if (![...projSel.options].some((o) => o.value === project)) {
            const opt = document.createElement('option');
            opt.value = project;
            opt.textContent = project;
            projSel.appendChild(opt);
          }
          projSel.value = projSel.value === project ? '' : project;
        }
        loadCrashes(projSel.value).catch(() => {});
        return;
      }
      const sel = document.getElementById('crash-sev-filter');
      if (!sel) return;
      if (!sev) sel.value = '';
      else sel.value = sel.value === sev ? '' : sev;
      paintCrashInvestigate();
    });
  });

  harvestState.lastUnique = unique;
  harvestState.lastIpCount = ipHits;
}

function paintHarvestViews() {
  renderScreamCanisters({
    rackId: 'scream-canister-rack',
    statusId: 'scream-harvest-status',
    pressureId: 'scream-harvest-pressure',
    mode: harvestState.mode,
  });
  renderScreamCanisters({
    rackId: 'dash-canister-rack',
    statusId: 'dash-harvest-status',
    compact: true,
    mode: 'projects',
  });
  // Compact rack on the Fuzz campaign so canisters stay visible while live-logging.
  renderScreamCanisters({
    rackId: 'fuzz-canister-rack',
    statusId: 'fuzz-harvest-status',
    pressureId: 'fuzz-harvest-pressure',
    compact: true,
    mode: 'projects',
  });
}

async function refreshHarvest(opts = {}) {
  // Prefer unfiltered crashes so each test keeps its own canister visible.
  const project = opts.projectFilter != null
    ? opts.projectFilter
    : (opts.singleProject
      ? (opts.project || document.getElementById('crash-filter')?.value || stalkProject || '')
      : '');
  const url = project ? `/api/crashes?project=${encodeURIComponent(project)}` : '/api/crashes';
  try {
    const crashes = await api.get(url);
    const prev = harvestState.lastUnique;
    const prevIp = harvestState.lastIpCount;
    harvestState.all = crashes || [];
    if (opts.syncCrashState || document.getElementById('view-crashes')?.classList.contains('visible')) {
      // Crash list may be filtered; harvest rack uses full harvestState.all
      if (opts.repaintInvestigate) paintCrashInvestigate();
      else paintHarvestViews();
    } else {
      paintHarvestViews();
    }
    const next = harvestUniqueCount(harvestState.all);
    const nextIp = harvestIpControlCount(harvestState.all);
    if (opts.toast && nextIp > prevIp) {
      const hit = (harvestState.all || []).find(crashIpControlled);
      flashScreamBottled(hit?.project || opts.project || harvestState.liveProject || 'lab', { ipControlled: true });
    } else if (opts.toast && next > prev) {
      flashScreamBottled(opts.project || harvestState.liveProject || 'lab');
    }
    return harvestState.all;
  } catch {
    paintHarvestViews();
    return harvestState.all;
  }
}

function scheduleHarvestRefresh(opts = {}) {
  clearTimeout(harvestState.refreshTimer);
  harvestState.refreshTimer = setTimeout(() => {
    refreshHarvest(opts).catch(() => {});
  }, opts.immediate ? 0 : 450);
}

function paintCrashInvestigate() {
  applyCrashFilters();
  renderActiveCrashFilters();
  // Keep the per-test rack on the full harvest snapshot.
  paintHarvestViews();
  renderCrashTimeline();
  renderCrashClassBars();
  renderCrashClusterChips();
  renderCrashEventList();
  const pending = crashState.pendingSelectId;
  if (pending) {
    crashState.pendingSelectId = null;
    selectCrashById(pending);
    return;
  }
  if (crashState.selectedId && crashState.filtered.some((c) => c.id === crashState.selectedId)) {
    crashState.selectedIndex = crashState.filtered.findIndex((c) => c.id === crashState.selectedId);
    renderCrashEventList();
  } else if (crashState.filtered.length) {
    selectCrashById(crashState.filtered[0].id);
  } else {
    crashState.selectedId = null;
    crashState.selectedIndex = -1;
    const box = document.getElementById('crash-detail');
    const metaEl = document.getElementById('crash-invest-meta');
    if (metaEl) metaEl.textContent = '';
    if (box) {
      box.innerHTML = '<p class="empty">Brush the timeline or pick an event to investigate.</p>';
    }
  }
}

async function loadCrashes(project = '') {
  const url = project ? `/api/crashes?project=${encodeURIComponent(project)}` : '/api/crashes';
  const clusterUrl = project ? `/api/crashes/clusters?project=${encodeURIComponent(project)}` : '/api/crashes/clusters';
  const [crashes, clusters] = await Promise.all([
    api.get(url),
    api.get(clusterUrl).catch(() => []),
  ]);
  crashState.all = crashes || [];
  crashState.clusters = clusters || [];
  harvestState.all = crashState.all;
  crashState.bucketKey = null;
  crashState.classKey = null;
  crashState.clusterKey = null;
  const uniq = document.getElementById('crash-unique-only');
  if (uniq) crashState.uniqueOnly = uniq.checked;
  paintCrashInvestigate();
}

document.getElementById('crash-filter')?.addEventListener('change', (e) => {
  loadCrashes(e.target.value);
});
document.getElementById('crash-sev-filter')?.addEventListener('change', () => paintCrashInvestigate());
document.getElementById('crash-sort')?.addEventListener('change', () => paintCrashInvestigate());
document.getElementById('crash-unique-only')?.addEventListener('change', () => paintCrashInvestigate());
document.getElementById('crash-refresh')?.addEventListener('click', () => {
  loadCrashes(document.getElementById('crash-filter')?.value || '');
});
document.getElementById('crash-clear-filters')?.addEventListener('click', () => {
  crashState.bucketKey = null;
  crashState.classKey = null;
  crashState.clusterKey = null;
  const sevEl = document.getElementById('crash-sev-filter');
  if (sevEl) sevEl.value = '';
  const sortEl = document.getElementById('crash-sort');
  if (sortEl) sortEl.value = 'best';
  const uniq = document.getElementById('crash-unique-only');
  if (uniq) uniq.checked = true;
  crashState.uniqueOnly = true;
  paintCrashInvestigate();
});
document.getElementById('crash-prev')?.addEventListener('click', () => selectCrashOffset(-1));
document.getElementById('crash-next')?.addEventListener('click', () => selectCrashOffset(1));
document.getElementById('crash-next-unique')?.addEventListener('click', () => selectNextUnique());

document.addEventListener('keydown', (ev) => {
  if (!document.getElementById('view-crashes')?.classList.contains('visible')) return;
  if (ev.target.matches('input, textarea, select')) return;
  if (ev.key === 'ArrowDown' || ev.key === 'j') {
    ev.preventDefault();
    selectCrashOffset(1);
  } else if (ev.key === 'ArrowUp' || ev.key === 'k') {
    ev.preventDefault();
    selectCrashOffset(-1);
  } else if (ev.key === 'n' || ev.key === 'N') {
    ev.preventDefault();
    selectNextUnique();
  } else if (ev.key === 'u' || ev.key === 'U') {
    ev.preventDefault();
    const uniq = document.getElementById('crash-unique-only');
    if (uniq) {
      uniq.checked = !uniq.checked;
      paintCrashInvestigate();
    }
  }
});

document.getElementById('dash-open-canisters')?.addEventListener('click', () => {
  switchView('crashes');
  loadCrashes(document.getElementById('crash-filter')?.value || stalkProject || '').catch(() => {});
});
document.getElementById('fuzz-open-canisters')?.addEventListener('click', () => {
  switchView('crashes');
  loadCrashes(document.getElementById('crash-filter')?.value || stalkProject || '').catch(() => {});
});
document.getElementById('scream-harvest-mode')?.addEventListener('change', (e) => {
  harvestState.mode = e.target.value === 'severity' ? 'severity' : 'projects';
  paintHarvestViews();
});

function applyScreamHarvestPrefs({ canisters, animations, persist = true } = {}) {
  const cansOn = canisters !== false;
  const animOn = animations === true;
  document.documentElement.setAttribute('data-scream-canisters', cansOn ? 'on' : 'off');
  document.documentElement.setAttribute('data-scream-anim', animOn ? 'on' : 'off');
  const en = document.getElementById('scream-harvest-enabled');
  const an = document.getElementById('scream-harvest-anim');
  if (en) en.checked = cansOn;
  if (an) an.checked = animOn;
  if (persist) {
    try {
      localStorage.setItem('randfuzz.screamCanisters', cansOn ? '1' : '0');
      localStorage.setItem('randfuzz.screamAnimations', animOn ? '1' : '0');
    } catch { /* ignore */ }
  }
  paintHarvestViews();
}

document.getElementById('scream-harvest-enabled')?.addEventListener('change', async (e) => {
  const cansOn = !!e.target.checked;
  applyScreamHarvestPrefs({
    canisters: cansOn,
    animations: document.getElementById('scream-harvest-anim')?.checked,
  });
  try { await api.put('/api/ui/prefs', { screamCanisters: cansOn }); } catch { /* localStorage still restores */ }
});
document.getElementById('scream-harvest-anim')?.addEventListener('change', async (e) => {
  const animOn = !!e.target.checked;
  applyScreamHarvestPrefs({
    canisters: document.getElementById('scream-harvest-enabled')?.checked !== false,
    animations: animOn,
  });
  try { await api.put('/api/ui/prefs', { screamAnimations: animOn }); } catch { /* localStorage still restores */ }
});

async function initScreamHarvestPrefs() {
  loadSeenHarvestProjects();
  let cansOn = true;
  let animOn = false;
  try {
    const localC = localStorage.getItem('randfuzz.screamCanisters');
    const localA = localStorage.getItem('randfuzz.screamAnimations');
    if (localC === '0') cansOn = false;
    if (localC === '1') cansOn = true;
    if (localA === '1') animOn = true;
    if (localA === '0') animOn = false;
  } catch { /* ignore */ }
  try {
    const prefs = await api.get('/api/ui/prefs');
    if (typeof prefs?.screamCanisters === 'boolean') cansOn = prefs.screamCanisters;
    if (typeof prefs?.screamAnimations === 'boolean') animOn = prefs.screamAnimations;
  } catch { /* keep local defaults */ }
  applyScreamHarvestPrefs({ canisters: cansOn, animations: animOn, persist: true });
}


let hub;

async function connectHub() {
  hub = new signalR.HubConnectionBuilder().withUrl('/hubs/fuzz').withAutomaticReconnect().build();

  hub.onreconnected(async () => {
    try {
      await syncFuzzSession();
      appendLogUnique('Reconnected — resynced live session', 'info');
    } catch { /* poll will retry */ }
  });

  hub.on('fuzzStarted', (e) => {
    setStatus(`Running ${e.project}…`);
    startBtn.disabled = true;
    stopBtn.disabled = false;
    stalkProject = e.project || stalkProject;
    harvestState.liveProject = e.project || stalkProject || null;
    markHarvestProjectSeen(harvestState.liveProject);
    stalkServerTimeline = [];
    stalkLiveTimeline = [];
    stalkCrashIdByIteration.clear();
    stalkFollowLive = true;
    stalkSelection = null;
    paintHarvestViews();
    if (document.getElementById('view-dashboard').classList.contains('visible'))
      loadDashboard({ applyWidgets: true, followLive: true }).catch(() => {});
  });

  hub.on('fuzzLog', (e) => {
    const kind = (e.kind || 'info').toLowerCase();
    appendLogUnique(e.message || '', kind, e.at);
    if (kind === 'crash') {
      scheduleHarvestRefresh({
        project: stalkProject,
        toast: true,
        syncCrashState: true,
        repaintInvestigate: document.getElementById('view-crashes')?.classList.contains('visible'),
      });
    }
  });

  hub.on('fuzzIteration', (e) => {
    // Rich lines come from fuzzLog; iteration only updates status / stalker timeline
    setStatus(`iter ${e.iteration} · corpus ${e.corpusSize} · edges ${e.coverageEdgeTotal}`);
    stalkLiveTimeline.push({
      index: stalkLiveTimeline.length,
      kind: e.crashed ? 'crash' : e.newCoverage ? 'novel' : 'hit',
      label: e.mutator,
      iteration: e.iteration,
      crashed: !!e.crashed,
      newEdges: e.newEdgeCount || 0,
      crashId: stalkCrashIdByIteration.get(Number(e.iteration)) || null,
    });
    if (stalkLiveTimeline.length > 200) stalkLiveTimeline = stalkLiveTimeline.slice(-200);
    if (e.crashed) {
      scheduleHarvestRefresh({
        project: stalkProject,
        toast: true,
        syncCrashState: true,
        repaintInvestigate: document.getElementById('view-crashes')?.classList.contains('visible'),
      });
    }
    if (document.getElementById('view-dashboard').classList.contains('visible')) {
      // Keep growing the bar strip even when pinned; do not clobber CFG/widgets.
      renderTimeline(mergeTimeline());
      if (stalkFollowLive) {
        document.getElementById('stalk-status').textContent = e.crashed ? 'Crash Detected' : 'Tracing';
        document.getElementById('stalk-status').className = statusClass(e.crashed ? 'Crash Detected' : 'Tracing');
      }
    }
  });

  hub.on('fuzzCompleted', (e) => {
    appendLogUnique(`Done — ${e.iterations} iters, ${e.crashesFound} crashes, +${e.corpusAdded} corpus`, 'ok');
    setStatus('Completed');
    startBtn.disabled = false;
    stopBtn.disabled = true;
    harvestState.liveProject = null;
    resolveCrashIdForIteration(-1).finally(() => {
      loadDashboard({
        applyWidgets: stalkFollowLive,
        force: stalkFollowLive,
      }).catch(() => {});
    });
    loadCrashes();
    scheduleHarvestRefresh({ project: stalkProject, immediate: true, syncCrashState: true });
  });

  hub.on('fuzzStopped', (e) => {
    appendLogUnique(`Stopped: ${e.reason}`, 'warn');
    setStatus('Stopped');
    startBtn.disabled = false;
    stopBtn.disabled = true;
    harvestState.liveProject = null;
    paintHarvestViews();
    loadDashboard({ applyWidgets: stalkFollowLive, force: stalkFollowLive }).catch(() => {});
  });

  hub.on('fuzzError', (e) => {
    appendLogUnique(`Error!!!! ${e.message}`, 'crash');
    setStatus('Error');
    startBtn.disabled = false;
    stopBtn.disabled = true;
  });

  await hub.start();
}

/* —— Campaign recording profiles (UI presets → same fuzz start flags) —— */
const RECORDING_CHECKBOX_IDS = {
  procmon: 'fuzz-procmon',
  tcpvcon: 'fuzz-tcpvcon',
  procdump: 'fuzz-procdump',
  pktmon: 'fuzz-pktmon',
  tshark: 'fuzz-tshark',
  etw: 'fuzz-etw',
  debugview: 'fuzz-debugview',
  sysinternals: 'fuzz-sysinternals-snap',
  strings: 'fuzz-strings-crash',
};

const RECORDING_PROFILES = {
  off: {
    procmon: false, tcpvcon: false, procdump: false, pktmon: false, tshark: false,
    etw: false, debugview: false, sysinternals: false, strings: false,
  },
  'first-triage': {
    procmon: true, tcpvcon: false, procdump: false, pktmon: false, tshark: false,
    etw: false, debugview: false, sysinternals: true, strings: false,
  },
  // Same wired flags as first-triage — surfaces RE companions (API Monitor / Frida).
  'parser-re': {
    procmon: true, tcpvcon: false, procdump: false, pktmon: false, tshark: false,
    etw: false, debugview: false, sysinternals: true, strings: false,
  },
  network: {
    procmon: true, tcpvcon: true, procdump: false, pktmon: true, tshark: true,
    etw: false, debugview: false, sysinternals: true, strings: false,
  },
  'deep-dive': {
    procmon: true, tcpvcon: true, procdump: false, pktmon: true, tshark: true,
    etw: true, debugview: true, sysinternals: true, strings: true,
  },
};

let applyingRecordingProfile = false;

function readRecordingFlags() {
  const flags = {};
  for (const [key, id] of Object.entries(RECORDING_CHECKBOX_IDS)) {
    flags[key] = document.getElementById(id)?.checked === true;
  }
  return flags;
}

function flagsMatchProfile(flags, profile) {
  return Object.keys(RECORDING_CHECKBOX_IDS).every((k) => !!flags[k] === !!profile[k]);
}

function matchRecordingProfileName(flags = readRecordingFlags()) {
  for (const [name, profile] of Object.entries(RECORDING_PROFILES)) {
    // parser-re shares first-triage flags — only selectable from the dropdown
    if (name === 'parser-re') continue;
    if (flagsMatchProfile(flags, profile)) return name;
  }
  return 'custom';
}

function updateRecordingElevHint(profileName) {
  const elev = document.getElementById('fuzz-recording-elev');
  if (!elev) return;
  elev.classList.toggle('hidden', profileName !== 'network' && profileName !== 'deep-dive');
}

function updateReCompanionsPanel(profileName) {
  const panel = document.getElementById('fuzz-re-companions');
  const note = document.getElementById('fuzz-re-companions-note');
  const isParserRe = profileName === 'parser-re';
  if (note) note.classList.toggle('hidden', !isParserRe);
  if (panel && isParserRe) panel.open = true;
}

function applyRecordingProfile(name) {
  const profile = RECORDING_PROFILES[name];
  const select = document.getElementById('fuzz-recording-profile');
  const advanced = document.getElementById('fuzz-recording-advanced');
  if (select) select.value = name === 'custom' ? 'custom' : name;
  if (!profile) {
    if (advanced && name === 'custom') advanced.open = true;
    updateRecordingElevHint(name);
    updateReCompanionsPanel(name);
    return;
  }
  applyingRecordingProfile = true;
  for (const [key, id] of Object.entries(RECORDING_CHECKBOX_IDS)) {
    const el = document.getElementById(id);
    if (el) el.checked = !!profile[key];
  }
  applyingRecordingProfile = false;
  updateRecordingElevHint(name);
  updateReCompanionsPanel(name);
  if (advanced && name === 'custom') advanced.open = true;
}

function initRecordingProfiles() {
  const select = document.getElementById('fuzz-recording-profile');
  if (!select) return;

  const initial = select.value || 'first-triage';
  if (initial !== 'custom') applyRecordingProfile(initial);
  else {
    updateRecordingElevHint('custom');
    updateReCompanionsPanel('custom');
  }

  select.addEventListener('change', () => {
    const name = select.value;
    if (name === 'custom') {
      const advanced = document.getElementById('fuzz-recording-advanced');
      if (advanced) advanced.open = true;
      updateRecordingElevHint('custom');
      updateReCompanionsPanel('custom');
      return;
    }
    applyRecordingProfile(name);
  });

  for (const id of Object.values(RECORDING_CHECKBOX_IDS)) {
    document.getElementById(id)?.addEventListener('change', () => {
      if (applyingRecordingProfile) return;
      const matched = matchRecordingProfileName();
      select.value = matched;
      updateRecordingElevHint(matched);
      updateReCompanionsPanel(matched);
      if (matched === 'custom') {
        const advanced = document.getElementById('fuzz-recording-advanced');
        if (advanced) advanced.open = true;
      }
    });
  }
}

initRecordingProfiles();

document.getElementById('fuzz-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  // New session only — never clear merely because the user left/returned to Fuzz.
  clearFuzzLog();
  try {
    await api.post('/api/fuzz/start', {
      configPath: document.getElementById('fuzz-target').value,
      maxIterations: Number(document.getElementById('fuzz-iterations').value),
      dryRun: document.getElementById('fuzz-dry-run').checked,
      coverageGuided: document.getElementById('fuzz-coverage').checked,
      debuggerMode: document.getElementById('fuzz-debugger').value,
      debuggerKind: document.getElementById('fuzz-debugger-kind').value,
      debuggerOpenOnCrash: document.getElementById('fuzz-open-on-crash').checked,
      procmonCapture: document.getElementById('fuzz-procmon')?.checked === true,
      tcpvconCapture: document.getElementById('fuzz-tcpvcon')?.checked === true,
      procdumpOnCrash: document.getElementById('fuzz-procdump')?.checked === true,
      pktmonCapture: document.getElementById('fuzz-pktmon')?.checked === true,
      tsharkCapture: document.getElementById('fuzz-tshark')?.checked === true,
      etwCapture: document.getElementById('fuzz-etw')?.checked === true,
      debugViewCapture: document.getElementById('fuzz-debugview')?.checked === true,
      sysinternalsSnapshots: document.getElementById('fuzz-sysinternals-snap')?.checked === true,
      stringsOnCrash: document.getElementById('fuzz-strings-crash')?.checked === true,
    });
    appendLog('Session accepted…');
  } catch (err) {
    appendLog(err.message, 'crash');
  }
});

stopBtn.addEventListener('click', async () => {
  stopBtn.disabled = true;
  setStatus('stopping: Sending stop…');
  try {
    const s = await api.post('/api/fuzz/stop', {});
    applyFuzzSessionStatus(s);
    appendLogUnique('Stop requested — waiting for teardown…', 'warn');
  } catch (err) {
    appendLogUnique(err.message, 'crash');
    try {
      await syncFuzzSession({ fetchLogs: false });
    } catch { /* ignore */ }
  }
});

document.getElementById('fuzz-stop-recorders')?.addEventListener('click', async () => {
  try {
    const r = await api.post('/api/recorders/stop', {});
    appendLog(r.message || 'Recording stopped', 'warn');
    if (Array.isArray(r.items)) {
      for (const it of r.items) {
        const path = it.path ? ` → ${it.path}` : '';
        appendLog(`  ${it.name}${path}: ${it.status}`, 'info');
      }
    }
  } catch (err) {
    appendLog(err.message, 'crash');
  }
});

document.getElementById('fuzz-log-clear')?.addEventListener('click', () => {
  clearFuzzLog();
});

document.getElementById('fuzz-attach-dbg')?.addEventListener('click', async () => {
  try {
    const kind = document.getElementById('fuzz-debugger-kind').value;
    const r = await api.post('/api/debug/attach', { kind, go: true });
    appendLog(r.message || `Attached ${kind}`, 'cov');
  } catch (err) {
    appendLog(err.message, 'crash');
  }
});

document.getElementById('fuzz-doctor').addEventListener('click', async () => {
  const box = document.getElementById('fuzz-doctor-result');
  box.classList.remove('hidden');
  box.textContent = 'Running preflight…';
  try {
    const configPath = document.getElementById('fuzz-target').value;
    const plat = (typeof platformState !== 'undefined' && platformState.selected) || 'auto';
    const report = await api.get(
      `/api/doctor?configPath=${encodeURIComponent(configPath)}&platform=${encodeURIComponent(plat)}`);
    const scopeNote = report.platform
      ? `<div class="hint" style="margin-bottom:0.35rem">Scoped to <strong>${report.platform}</strong> (host ${report.hostPlatform})</div>`
      : '';
    box.innerHTML = scopeNote + report.checks.map((c) => {
      const cls = c.status === 'ok' ? 'cov' : c.status === 'warn' ? '' : 'crash';
      return `<div class="${cls}">[${c.status}] ${c.id}: ${c.message}</div>`;
    }).join('') + `<div style="margin-top:0.5rem"><strong>${report.ready ? 'Ready' : 'Not ready'}</strong></div>`;
  } catch (err) {
    box.textContent = err.message;
  }
});

async function loadGraphView() {
  const targets = (await api.get('/api/targets')).filter(isVisibleTarget);
  const sel = document.getElementById('graph-target');
  if (!sel.options.length) {
    sel.innerHTML = targets.map((t) => `<option value="${t.configPath}">${t.name} [${t.kind}]</option>`).join('');
    const ftp = targets.find((t) => t.name === 'vulnftp');
    if (ftp) sel.value = ftp.configPath;
  }
}

let graphEditState = { commands: [], edges: [], start: '', mutate: '', configPath: '' };

function fillGraphSelect(sel, commands, selected, allowEmpty) {
  if (!sel) return;
  const opts = [];
  if (allowEmpty) opts.push('<option value="">—</option>');
  opts.push(...(commands || []).map((c) =>
    `<option value="${escapeAttr(c)}" ${c === selected ? 'selected' : ''}>${escapeAttr(c)}</option>`));
  sel.innerHTML = opts.join('');
}

function renderGraphEdgeEditor() {
  const edgesEl = document.getElementById('graph-edges');
  const cmds = graphEditState.commands || [];
  if (!edgesEl) return;
  if (!cmds.length) {
    edgesEl.innerHTML = '<p class="hint">No sessionCommands — add a TCP session (Scare Floor Apply) first.</p>';
    return;
  }
  const cmdOpts = (selected) => cmds.map((c) =>
    `<option value="${escapeAttr(c)}" ${c === selected ? 'selected' : ''}>${escapeAttr(c)}</option>`).join('');
  const edges = graphEditState.edges.length
    ? graphEditState.edges
    : [{ from: cmds[0], when: '', to: cmds[0] }];
  graphEditState.edges = edges;
  edgesEl.innerHTML = `<table><thead><tr><th>From</th><th>When (contains)</th><th>To</th><th></th></tr></thead>
    <tbody>${edges.map((e, i) => `<tr>
      <td><select data-ge-from="${i}">${cmdOpts(e.from)}</select></td>
      <td><input data-ge-when="${i}" value="${escapeAttr(e.when || '')}" placeholder="331" /></td>
      <td><select data-ge-to="${i}">${cmdOpts(e.to)}</select></td>
      <td><button type="button" class="btn" data-ge-del="${i}">×</button></td>
    </tr>`).join('')}</tbody></table>`;

  edgesEl.querySelectorAll('[data-ge-from]').forEach((sel) => {
    sel.addEventListener('change', () => {
      graphEditState.edges[Number(sel.dataset.geFrom)].from = sel.value;
    });
  });
  edgesEl.querySelectorAll('[data-ge-to]').forEach((sel) => {
    sel.addEventListener('change', () => {
      graphEditState.edges[Number(sel.dataset.geTo)].to = sel.value;
    });
  });
  edgesEl.querySelectorAll('[data-ge-when]').forEach((inp) => {
    inp.addEventListener('change', () => {
      graphEditState.edges[Number(inp.dataset.geWhen)].when = inp.value;
    });
  });
  edgesEl.querySelectorAll('[data-ge-del]').forEach((btn) => {
    btn.addEventListener('click', () => {
      graphEditState.edges.splice(Number(btn.dataset.geDel), 1);
      renderGraphEdgeEditor();
    });
  });
}

async function renderGraph(configPath, reportOverride) {
  const status = document.getElementById('graph-status');
  const meta = document.getElementById('graph-meta');
  const diagram = document.getElementById('graph-diagram');
  const yamlEl = document.getElementById('graph-yaml');

  status.textContent = 'Loading…';
  const report = reportOverride
    || await api.get(`/api/graph?configPath=${encodeURIComponent(configPath)}`);

  graphEditState = {
    configPath,
    commands: report.commands || [],
    edges: (report.edges || []).map((e) => ({ from: e.from, when: e.when || '', to: e.to })),
    start: report.start || (report.commands || [])[0] || '',
    mutate: report.mutate || '',
  };
  fillGraphSelect(document.getElementById('graph-start'), graphEditState.commands, graphEditState.start, false);
  fillGraphSelect(document.getElementById('graph-mutate'), graphEditState.commands, graphEditState.mutate, true);

  if (!report.hasGraph && !(report.commands || []).length) {
    status.textContent = `${report.project}: no sessionCommands / sessionGraph yet.`;
    status.className = 'status-box warn';
    meta.innerHTML = '<p class="hint">Create a TCP session on Scare Floor (Apply to Campaign), then edit the graph here.</p>';
    diagram.innerHTML = '';
    renderGraphEdgeEditor();
    yamlEl.value = '';
    return;
  }

  status.className = `status-box ${report.valid || !report.hasGraph ? 'ok' : 'crash'}`;
  status.textContent = report.hasGraph
    ? (report.valid
      ? `Valid graph — start=${report.start}, mutate=${report.mutate || '—'}`
      : 'Invalid graph — fix errors, then Save')
    : `${report.project}: no sessionGraph yet — add edges below and Save`;

  const warnHtml = (report.warnings || []).map((w) => `<div class="warn">⚠ ${escapeAttr(w)}</div>`).join('');
  const errHtml = (report.errors || []).map((e) => `<div class="crash">✗ ${escapeAttr(e)}</div>`).join('');
  meta.innerHTML = `
    <p><strong>${escapeAttr(report.project)}</strong> · edit edges → <strong>Save graph</strong></p>
    ${errHtml}${warnHtml}
    <p class="hex">Commands: ${(report.commands || []).map((c) => `<code>${escapeAttr(c)}</code>`).join(' ')}</p>`;

  yamlEl.value = report.yamlSnippet || '';
  renderGraphEdgeEditor();

  if (report.mermaid) {
    diagram.innerHTML = `<pre class="mermaid">${report.mermaid}</pre>`;
    if (window.mermaid) {
      mermaid.initialize({ startOnLoad: false, theme: 'dark', securityLevel: 'loose' });
      await mermaid.run({ nodes: diagram.querySelectorAll('.mermaid') });
    }
  } else {
    diagram.innerHTML = '<p class="empty">No edges yet — add some and Save.</p>';
  }
}

document.getElementById('graph-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await renderGraph(document.getElementById('graph-target').value);
  } catch (err) {
    document.getElementById('graph-status').textContent = err.message;
  }
});

document.getElementById('graph-edge-add')?.addEventListener('click', () => {
  const cmds = graphEditState.commands || [];
  if (!cmds.length) return;
  graphEditState.edges.push({ from: cmds[0], when: '', to: cmds[Math.min(1, cmds.length - 1)] });
  renderGraphEdgeEditor();
});

document.getElementById('graph-save')?.addEventListener('click', async () => {
  const configPath = document.getElementById('graph-target')?.value || graphEditState.configPath;
  if (!configPath) return;
  const start = document.getElementById('graph-start')?.value || graphEditState.start;
  const mutate = document.getElementById('graph-mutate')?.value || null;
  // Flush edge inputs
  document.querySelectorAll('#graph-edges [data-ge-when]').forEach((inp) => {
    const i = Number(inp.dataset.geWhen);
    if (graphEditState.edges[i]) graphEditState.edges[i].when = inp.value;
  });
  try {
    const report = await api.post('/api/graph', {
      configPath,
      start,
      mutate: mutate || null,
      edges: graphEditState.edges,
    });
    await renderGraph(configPath, report);
    document.getElementById('graph-status').textContent =
      (report.valid ? 'Saved — valid graph. ' : 'Saved — check errors. ') +
      `start=${report.start}, mutate=${report.mutate || '—'}`;
  } catch (err) {
    document.getElementById('graph-status').textContent = err.message;
  }
});

document.getElementById('graph-copy-yaml').addEventListener('click', async () => {
  const yaml = document.getElementById('graph-yaml').value;
  if (!yaml) return;
  await navigator.clipboard.writeText(yaml);
  document.getElementById('graph-status').textContent = 'YAML copied to clipboard.';
});

let selectedProxyMessage = null;

async function loadModels() {
  const models = await api.get('/api/protocols');
  const el = document.getElementById('models-list');
  if (!models.length) {
    el.innerHTML = '<p class="empty">No protocols in projects/protocols/</p>';
    return;
  }
  el.innerHTML = models.map((m) => `
    <div class="phase">
      <h3>${m.name}</h3>
      <p class="hex">${m.description || m.path}</p>
      <table><thead><tr><th>Field</th><th>Offset</th><th>Len</th><th>Type</th><th>Mutable</th></tr></thead>
        <tbody>${(m.fields || []).map((f) => `<tr>
          <td><code>${f.name}</code></td><td>${f.offset}</td><td>${f.length}</td>
          <td><code>${f.type || 'bytes'}</code></td>
          <td>${f.mutable ? '✓' : '—'}</td></tr>`).join('')}
        </tbody></table>
    </div>`).join('');
}

async function loadBundlesView() {
  const targets = (await api.get('/api/targets')).filter(isVisibleTarget);
  const sel = document.getElementById('bundle-export-target');
  if (sel) {
    sel.innerHTML = targets.map((t) => `<option value="${t.configPath}">${t.name}</option>`).join('');
  }
  const opts = targets.map((t) => `<option value="${t.name}">${t.name}</option>`).join('');
  const packSel = document.getElementById('crashpack-export-project');
  const pullSel = document.getElementById('crashpack-pull-project');
  if (packSel) packSel.innerHTML = opts;
  if (pullSel) pullSel.innerHTML = opts;

  const agentInput = document.getElementById('labs-agent-url');
  const pullAgent = document.getElementById('crashpack-pull-agent');
  if (agentInput && pullAgent && !pullAgent.value.trim() && agentInput.value.trim()) {
    pullAgent.value = agentInput.value.trim();
  }
}

function applyRemoteLabChrome() {
  const host = (location.hostname || '').toLowerCase();
  const isLoopback = host === 'localhost' || host === '127.0.0.1' || host === '::1';
  const badge = document.getElementById('remote-lab-badge');
  const tagline = document.getElementById('brand-tagline');
  if (!isLoopback) {
    document.body.classList.add('remote-lab');
    if (badge) badge.classList.remove('hidden');
    if (tagline) tagline.textContent = 'Target Runtime lab · fuzz here for dumps + lens';
  }
}

document.querySelectorAll('[data-view-jump]').forEach((el) => {
  el.addEventListener('click', () => {
    const name = el.getAttribute('data-view-jump');
    if (name) switchView(name);
  });
});

document.getElementById('bundle-export-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const out = document.getElementById('bundle-export-result');
  try {
    const body = {
      configPath: document.getElementById('bundle-export-target').value,
    };
    const customOut = document.getElementById('bundle-export-path').value.trim();
    if (customOut) body.outputPath = customOut;
    const result = await api.post('/api/bundle/export', body);
    out.textContent = `Exported ${Math.round((result.sizeBytes || 0) / 1024)} KB → ${result.path}`;
  } catch (err) {
    out.textContent = err.message;
  }
});

document.getElementById('bundle-import-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const out = document.getElementById('bundle-import-result');
  try {
    const body = { zipPath: document.getElementById('bundle-import-path').value.trim() };
    const dest = document.getElementById('bundle-import-out').value.trim();
    if (dest) body.outputDir = dest;
    const result = await api.post('/api/bundle/import', body);
    out.textContent = `Imported → ${result.path}`;
    await loadTargets();
    await loadBundlesView();
  } catch (err) {
    out.textContent = err.message;
  }
});

document.getElementById('crashpack-export-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const out = document.getElementById('crashpack-export-result');
  try {
    const body = {
      project: document.getElementById('crashpack-export-project').value,
      includeRuns: document.getElementById('crashpack-export-runs').checked,
    };
    const customOut = document.getElementById('crashpack-export-path').value.trim();
    if (customOut) body.outputPath = customOut;
    const result = await api.post('/api/crashes/pack', body);
    out.textContent =
      `Exported ${Math.round((result.sizeBytes || 0) / 1024)} KB → ${result.path}` +
      ` (crashes=${result.crashCount}, runs=${result.runCount})`;
  } catch (err) {
    out.textContent = err.message;
  }
});

document.getElementById('crashpack-import-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const out = document.getElementById('crashpack-import-result');
  try {
    const result = await api.post('/api/crashes/pack/import', {
      zipPath: document.getElementById('crashpack-import-path').value.trim(),
      overwriteFiles: true,
    });
    out.textContent = result.message || `Imported ${result.importedCrashes} crash(es) → ${result.crashesDir}`;
    await loadCrashes(document.getElementById('crash-filter')?.value || '').catch(() => {});
  } catch (err) {
    out.textContent = err.message;
  }
});

document.getElementById('crashpack-pull-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const out = document.getElementById('crashpack-pull-result');
  try {
    const agentUrl = document.getElementById('crashpack-pull-agent').value.trim();
    const project = document.getElementById('crashpack-pull-project').value;
    const body = { agentUrl, project, includeRuns: true };
    const agentToken = getLabsAgentToken();
    if (agentToken) body.agentToken = agentToken;
    const customOut = document.getElementById('crashpack-pull-path').value.trim();
    if (customOut) body.outputPath = customOut;
    const pulled = await api.post('/api/crashes/pack/pull', body);
    let msg =
      `Pulled ${Math.round((pulled.sizeBytes || 0) / 1024)} KB → ${pulled.path}` +
      ` (crashes=${pulled.crashCount}, runs=${pulled.runCount})`;
    if (document.getElementById('crashpack-pull-import').checked) {
      const imported = await api.post('/api/crashes/pack/import', {
        zipPath: pulled.path,
        overwriteFiles: true,
      });
      msg += `\n${imported.message || 'Imported.'}`;
      await loadCrashes(document.getElementById('crash-filter')?.value || '').catch(() => {});
    }
    out.textContent = msg;
  } catch (err) {
    out.textContent = err.message;
  }
});

async function loadCampaignView() {
  const campaigns = await api.get('/api/campaigns');
  const sel = document.getElementById('campaign-select');
  sel.innerHTML = campaigns.map((c) => `<option value="${c}">${c.split(/[/\\]/).pop()}</option>`).join('');

  const plugins = await api.get('/api/plugins');
  const pel = document.getElementById('plugin-list');
  if (!plugins.length) {
    pel.innerHTML = '<p class="empty">No plugins in plugins/ — see docs/RPP.md</p>';
  } else {
    pel.innerHTML = `<table><thead><tr><th>Name</th><th>Runtime</th><th>Hook</th></tr></thead>
      <tbody>${plugins.map((p) => `<tr><td><code>${p.name}</code></td><td>${p.runtime}</td><td>${p.hook}</td></tr>`).join('')}</tbody></table>`;
  }

  const st = await api.get('/api/campaign/status');
  document.getElementById('campaign-status').textContent = st.running
    ? `${st.phase}: ${st.completedRuns}/${st.totalRuns} runs, ${st.totalCrashes} crashes — ${st.lastMessage || ''}`
    : (st.lastMessage || 'Idle');
}

document.getElementById('campaign-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const path = document.getElementById('campaign-select').value;
  try {
    await api.post('/api/campaign/start', { campaignPath: path });
    await loadCampaignView();
  } catch (err) {
    document.getElementById('campaign-status').textContent = err.message;
  }
});

document.getElementById('campaign-stop').addEventListener('click', async () => {
  await api.post('/api/campaign/stop', {});
  await loadCampaignView();
});

async function loadProxy() {
  const status = await api.get('/api/proxy/status');
  document.getElementById('proxy-status').textContent = status.running
    ? `Running 127.0.0.1:${status.listenPort} → ${status.targetHost}:${status.targetPort} (${status.messageCount} msgs)`
    : (status.lastMessage || 'Idle');

  const messages = await api.get('/api/proxy/messages');
  const el = document.getElementById('proxy-messages');
  if (!messages.length) {
    el.innerHTML = '<p class="empty">No traffic yet — start proxy and connect a client to the listen port.</p>';
    return;
  }
  el.innerHTML = `<table><thead><tr><th>When</th><th>Dir</th><th>Len</th><th>Preview</th></tr></thead>
    <tbody>${messages.map((m) => `<tr class="clickable" data-id="${m.id}" data-hex="${m.hexPreview}">
      <td>${new Date(m.at).toLocaleTimeString()}</td>
      <td><code>${m.direction}</code></td><td>${m.length}</td>
      <td class="hex-preview">${m.hexPreview}</td></tr>`).join('')}</tbody></table>`;

  el.querySelectorAll('tr.clickable').forEach((row) => {
    row.addEventListener('click', () => {
      selectedProxyMessage = row.dataset.id;
      const box = document.getElementById('proxy-replay');
      box.classList.remove('hidden');
      document.getElementById('proxy-hex').value = row.dataset.hex.replace(' …', '');
    });
  });
}

document.getElementById('proxy-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api.post('/api/proxy/start', {
      listenPort: Number(document.getElementById('proxy-listen').value),
      targetHost: document.getElementById('proxy-host').value,
      targetPort: Number(document.getElementById('proxy-port').value),
      tag: 'web',
    });
    await loadProxy();
  } catch (err) {
    document.getElementById('proxy-status').textContent = err.message;
  }
});

document.getElementById('proxy-stop').addEventListener('click', async () => {
  await api.post('/api/proxy/stop', {});
  await loadProxy();
});

document.getElementById('proxy-replay-btn').addEventListener('click', async () => {
  if (!selectedProxyMessage) return;
  const hex = document.getElementById('proxy-hex').value.trim();
  try {
    await api.post('/api/proxy/replay', {
      messageId: selectedProxyMessage,
      editedHex: hex || null,
    });
    await loadProxy();
  } catch (err) {
    document.getElementById('proxy-status').textContent = err.message;
  }
});

function openScareFloorTab() {
  switchView('fuzz');
  document.querySelector('.fuzz-subtab[data-fuzz-tab="cases"]')?.click();
}

function hexToSpaced(hex) {
  const clean = String(hex || '').replace(/[^0-9a-fA-F]/g, '');
  const parts = [];
  for (let i = 0; i + 1 < clean.length; i += 2)
    parts.push(clean.slice(i, i + 2));
  return parts.join(' ');
}

async function importProxyHexToScareFloor(hexFull, pduName) {
  openScareFloorTab();
  await loadCaseBuilder().catch(() => {});
  const kind = (caseProfile?.kind || '').toLowerCase();
  if (kind !== 'tcp') {
    const status = document.getElementById('proxy-scare-status');
    if (status) {
      status.textContent =
        'Scare Floor needs a TCP Target profile selected (Working on project). Create/select TCP, then retry.';
    }
    document.getElementById('case-save-result').textContent =
      'Proxy import: switch Working on project to a [tcp] target, then send again.';
    focusCaseSessionPanel();
    return false;
  }
  const spaced = hexToSpaced(hexFull);
  const block = { op: 'hex', value: spaced, count: 16, format: 'u32le', role: 'fuzzable' };
  ensureCaseSessionMode();
  flushActiveSessionPdu();
  const name = pduName || `proxy${caseSessionSteps.length + 1}`;
  caseSessionSteps.push({
    name,
    readBanner: caseSessionSteps.length === 0,
    expectResponse: '',
    blocks: [block],
  });
  setActivePdu(caseSessionSteps.length - 1);
  const recipeName = document.getElementById('case-recipe-name');
  if (recipeName && !recipeName.value) recipeName.value = 'from-proxy';
  document.getElementById('case-save-result').textContent =
    `Imported proxy PDU “${name}” (${Math.floor(spaced.replace(/\s/g, '').length / 2)} bytes). Preview / Apply to Campaign.`;
  focusCaseSessionPanel();
  return true;
}

document.getElementById('proxy-to-scare')?.addEventListener('click', async () => {
  const status = document.getElementById('proxy-scare-status');
  if (!selectedProxyMessage) {
    if (status) status.textContent = 'Select a captured message first.';
    return;
  }
  try {
    // Prefer edited hex textarea if present, else full payload from API
    let hex = document.getElementById('proxy-hex')?.value?.trim() || '';
    hex = hex.replace(/…/g, '').trim();
    if (!hex || hex.length < 4) {
      const detail = await api.get(`/api/proxy/messages/${encodeURIComponent(selectedProxyMessage)}`);
      hex = detail.hexFull || '';
    }
    if (!hex) {
      if (status) status.textContent = 'No payload bytes on this message.';
      return;
    }
    const ok = await importProxyHexToScareFloor(hex, 'proxy');
    if (status) status.textContent = ok ? 'Sent to Scare Floor (Network session).' : 'See Scare Floor tip — need TCP project.';
  } catch (err) {
    if (status) status.textContent = err.message;
  }
});

document.getElementById('proxy-to-scare-session')?.addEventListener('click', async () => {
  const status = document.getElementById('proxy-scare-status');
  try {
    const messages = await api.get('/api/proxy/messages');
    // Oldest first; client→server only (common labels: c2s, client, →)
    const c2s = [...messages]
      .filter((m) => {
        const d = String(m.direction || '').toLowerCase();
        // TcpMitmProxy labels: "client→target" / "target→client"
        return d.includes('client→') || d.includes('client->') || d.includes('c2s');
      })
      .sort((a, b) => new Date(a.at) - new Date(b.at));
    const list = c2s.length ? c2s : [...messages].sort((a, b) => new Date(a.at) - new Date(b.at));
    if (!list.length) {
      if (status) status.textContent = 'No proxy messages to import.';
      return;
    }
    openScareFloorTab();
    await loadCaseBuilder().catch(() => {});
    if ((caseProfile?.kind || '').toLowerCase() !== 'tcp') {
      if (status) status.textContent = 'Select a TCP Target profile on Scare Floor first.';
      focusCaseSessionPanel();
      return;
    }
    caseSessionSteps = [];
    for (let i = 0; i < list.length; i++) {
      const detail = await api.get(`/api/proxy/messages/${encodeURIComponent(list[i].id)}`);
      const spaced = hexToSpaced(detail.hexFull || '');
      if (!spaced) continue;
      caseSessionSteps.push({
        name: `m${i + 1}`,
        readBanner: i === 0,
        expectResponse: '',
        blocks: [{ op: 'hex', value: spaced, count: 16, format: 'u32le', role: 'fuzzable' }],
      });
    }
    if (!caseSessionSteps.length) {
      if (status) status.textContent = 'Messages had no payload.';
      return;
    }
    caseActivePdu = caseSessionSteps.length - 1;
    caseSteps = mapApiSteps(caseSessionSteps[caseActivePdu].blocks);
    const recipeName = document.getElementById('case-recipe-name');
    if (recipeName) recipeName.value = 'from-proxy-session';
    const mut = document.getElementById('case-mutate-step');
    if (mut) mut.value = 'last';
    renderCaseSessionSteps();
    renderCaseSteps();
    document.getElementById('case-save-result').textContent =
      `Imported ${caseSessionSteps.length} PDU(s) from proxy. Preview all PDUs → Apply to Campaign.`;
    focusCaseSessionPanel();
    if (status) status.textContent = `Imported ${caseSessionSteps.length} PDU(s) to Scare Floor.`;
  } catch (err) {
    if (status) status.textContent = err.message;
  }
});

async function pollStatus() {
  try {
    const s = await api.get('/api/fuzz/status');
    applyFuzzSessionStatus(s);
    if (isFuzzSessionActive(s)) {
      stalkPollTick += 1;
      if (stalkPollTick % 3 === 0 && document.getElementById('view-dashboard').classList.contains('visible')) {
        // Pinned selection: refresh timeline/crash-id map only — keep stalker widgets frozen.
        loadDashboard({ applyWidgets: stalkFollowLive, force: stalkFollowLive }).catch(() => {});
      }
    } else {
      stalkPollTick = 0;
    }
  } catch { /* ignore */ }
}

/* —— Scare Floor (case recipes → seeds + dict → Campaign) —— */
let caseOps = [];
let caseSteps = [];
/** @type {null | { name: string, readBanner: boolean, expectResponse: string, blocks: any[], layers?: {name:string, blocks:any[]}[]|null }[]} */
let caseSessionSteps = null;
let caseActivePdu = 0;
/** @type {null | { name: string, blocks: any[] }[]} */
let caseLayers = null;
let caseActiveLayer = 0;

const LABS_AGENT_KEY = 'randall.labsAgentUrl';

function getLabsAgentUrl() {
  const input = document.getElementById('labs-agent-url');
  const fromInput = (input?.value || '').trim();
  if (fromInput) return fromInput;
  try {
    return (localStorage.getItem(LABS_AGENT_KEY) || '').trim();
  } catch {
    return '';
  }
}

function labsAgentQuery() {
  const agent = getLabsAgentUrl();
  if (!agent) return '';
  const token = getLabsAgentToken();
  let q = `?agent=${encodeURIComponent(agent)}`;
  if (token) q += `&agentToken=${encodeURIComponent(token)}`;
  return q;
}

function getLabsAgentToken() {
  try {
    return (localStorage.getItem('randallLabsAgentToken') || '').trim();
  } catch {
    return '';
  }
}

function persistLabsAgentUrl() {
  const input = document.getElementById('labs-agent-url');
  const tokInput = document.getElementById('labs-agent-token');
  const v = (input?.value || '').trim();
  const tok = (tokInput?.value || '').trim();
  try {
    if (v) localStorage.setItem(LABS_AGENT_KEY, v);
    else localStorage.removeItem(LABS_AGENT_KEY);
    if (tok) localStorage.setItem('randallLabsAgentToken', tok);
    else localStorage.removeItem('randallLabsAgentToken');
  } catch { /* ignore */ }
  const scope = document.getElementById('labs-scope-label');
  if (scope) scope.textContent = v ? `— remote ${v}` : '— this machine';
}

function updateLabsCampaignStrip(labs) {
  const summary = document.getElementById('labs-campaign-summary');
  const chips = document.getElementById('labs-campaign-chips');
  const badge = document.getElementById('labs-tab-badge');
  const running = (labs || []).filter((l) => l.running);
  const agent = getLabsAgentUrl();
  const where = agent ? `remote (${agent})` : 'this machine';

  if (summary) {
    summary.textContent = running.length
      ? `${running.length} running on ${where}`
      : `None running on ${where}`;
  }
  if (chips) {
    chips.innerHTML = running.length
      ? running.map((l) =>
        `<span class="labs-chip" title="PID ${l.pid ?? '?'}">${escapeAttr(l.name)} :${l.port}</span>`).join('')
      : '<span class="labs-chip off">idle</span>';
  }
  if (badge) {
    badge.textContent = String(running.length);
    badge.classList.toggle('hidden', running.length === 0);
  }
}

document.querySelectorAll('.fuzz-subtab').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.fuzz-subtab').forEach((b) => b.classList.toggle('active', b === btn));
    const tab = btn.dataset.fuzzTab;
    document.getElementById('fuzz-tab-campaign')?.classList.toggle('hidden', tab !== 'campaign');
    document.getElementById('fuzz-tab-cases')?.classList.toggle('hidden', tab !== 'cases');
    document.getElementById('fuzz-tab-labs')?.classList.toggle('hidden', tab !== 'labs');
    if (tab === 'cases') loadCaseBuilder().catch(() => {});
    if (tab === 'labs') {
      persistLabsAgentUrl();
      refreshLabs().catch(() => {});
    }
  });
});

document.getElementById('labs-open-tab')?.addEventListener('click', () => {
  document.querySelector('.fuzz-subtab[data-fuzz-tab="labs"]')?.click();
});

async function refreshLabs() {
  const tbody = document.getElementById('labs-tbody');
  const status = document.getElementById('labs-status');
  const catSel = document.getElementById('labs-category-filter');
  const category = (catSel && catSel.value && catSel.value !== 'all') ? catSel.value : '';
  const qBase = labsAgentQuery();
  const q = (() => {
    if (!category) return qBase;
    if (!qBase) return `?category=${encodeURIComponent(category)}`;
    return `${qBase}&category=${encodeURIComponent(category)}`;
  })();
  try {
    const labs = await api.get(`/api/labs${q}`);
    updateLabsCampaignStrip(labs);

    if (!tbody) return;
    tbody.innerHTML = (labs || []).map((lab) => {
      const state = !lab.exeExists
        ? '<span class="lab-badge miss">not built</span>'
        : lab.running
          ? (lab.reachable
            ? '<span class="lab-badge ok">running</span>'
            : '<span class="lab-badge warn">starting…</span>')
          : '<span class="lab-badge off">stopped</span>';
      const pid = lab.pid != null ? lab.pid : '—';
      const startDis = (!lab.exeExists || lab.running) ? 'disabled' : '';
      const stopDis = lab.running ? '' : 'disabled';
      const tags = (lab.tags || []).slice(0, 4).map((t) =>
        `<span class="lab-tag">${escapeAttr(t)}</span>`).join(' ');
      const diff = lab.difficulty
        ? `<span class="lab-diff lab-diff-${escapeAttr(lab.difficulty)}">${escapeAttr(lab.difficulty)}</span>`
        : '';
      return `<tr data-lab="${escapeAttr(lab.id)}">
        <td>
          <strong>${escapeAttr(lab.name)}</strong> ${diff}
          <div class="hint">${escapeAttr(lab.description || '')}</div>
          <div class="lab-tags">${tags}</div>
          <div class="hint"><code>${escapeAttr(lab.projectYaml || '')}</code>${lab.docsPath ? ` · <code>${escapeAttr(lab.docsPath)}</code>` : ''}</div>
        </td>
        <td><span class="lab-cat">${escapeAttr(lab.category || 'network')}</span></td>
        <td><code>${escapeAttr(lab.protocol)}/${lab.port}</code><div class="hint">${escapeAttr(lab.bindHint || '127.0.0.1')}</div></td>
        <td>${state}${lab.statusNote ? `<div class="hint">${escapeAttr(lab.statusNote)}</div>` : ''}</td>
        <td>${pid}</td>
        <td class="labs-actions">
          <button type="button" class="btn primary" data-lab-start="${escapeAttr(lab.id)}" ${startDis}>Start</button>
          <button type="button" class="btn" data-lab-stop="${escapeAttr(lab.id)}" ${stopDis}>Stop</button>
        </td>
      </tr>`;
    }).join('') || '<tr><td colspan="6" class="hint">No labs in this category</td></tr>';

    tbody.querySelectorAll('[data-lab-start]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        if (status) status.textContent = `Starting ${btn.dataset.labStart}…`;
        try {
          const r = await api.post(`/api/labs/${encodeURIComponent(btn.dataset.labStart)}/start${qBase}`, {});
          if (status) status.textContent = r.message || 'Started';
          await refreshLabs();
        } catch (err) {
          if (status) status.textContent = err.message;
        }
      });
    });
    tbody.querySelectorAll('[data-lab-stop]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        if (status) status.textContent = `Stopping ${btn.dataset.labStop}…`;
        try {
          const r = await api.post(`/api/labs/${encodeURIComponent(btn.dataset.labStop)}/stop${qBase}`, {});
          if (status) status.textContent = r.message || 'Stopped';
          await refreshLabs();
        } catch (err) {
          if (status) status.textContent = err.message;
        }
      });
    });

    const running = (labs || []).filter((l) => l.running).length;
    const where = getLabsAgentUrl() || 'local';
    if (status && !status.textContent.startsWith('Start') && !status.textContent.startsWith('Stop') && !status.textContent.startsWith('Agent'))
      status.textContent = `${running} running · ${(labs || []).length} labs · host: ${where}`;
    await refreshRuntime();
  } catch (err) {
    updateLabsCampaignStrip([]);
    if (tbody) tbody.innerHTML = `<tr><td colspan="6" class="hint">${escapeAttr(err.message)}</td></tr>`;
    if (status) status.textContent = err.message;
  }
}

async function refreshRuntime() {
  const tbody = document.getElementById('runtime-tbody');
  const status = document.getElementById('runtime-status');
  const q = labsAgentQuery();
  if (!tbody) return;
  try {
    const data = await api.get(`/api/runtime${q}`);
    const slots = data?.slots || [];
    tbody.innerHTML = slots.map((s) => {
      const state = s.running
        ? (s.portReachable
          ? '<span class="lab-badge ok">running</span>'
          : '<span class="lab-badge warn">started</span>')
        : '<span class="lab-badge off">stopped</span>';
      const port = s.waitPort != null ? `${escapeAttr(s.waitHost || '')}:${s.waitPort}` : '—';
      const stopDis = s.running ? '' : 'disabled';
      const restartDis = s.executable ? '' : 'disabled';
      return `<tr>
        <td>
          <strong>${escapeAttr(s.id)}</strong>
          <div class="hint"><code>${escapeAttr(s.executable || '')}</code></div>
          <div class="hint">${escapeAttr(s.message || '')}</div>
        </td>
        <td><code>${port}</code></td>
        <td>${state}</td>
        <td>${s.pid != null ? s.pid : '—'}</td>
        <td class="labs-actions">
          <button type="button" class="btn" data-rt-restart="${escapeAttr(s.id)}" ${restartDis}>Restart</button>
          <button type="button" class="btn" data-rt-stop="${escapeAttr(s.id)}" ${stopDis}>Stop</button>
        </td>
      </tr>`;
    }).join('') || '<tr><td colspan="5" class="hint">No runtime slots — <code>randall runtime start -c projects/…yaml</code></td></tr>';

    tbody.querySelectorAll('[data-rt-stop]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        if (status) status.textContent = `Stopping ${btn.dataset.rtStop}…`;
        try {
          const r = await api.post(`/api/runtime/${encodeURIComponent(btn.dataset.rtStop)}/stop${q}`, {});
          if (status) status.textContent = r.message || 'Stopped';
          await refreshRuntime();
        } catch (err) {
          if (status) status.textContent = err.message;
        }
      });
    });
    tbody.querySelectorAll('[data-rt-restart]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        if (status) status.textContent = `Restarting ${btn.dataset.rtRestart}…`;
        try {
          const r = await api.post(`/api/runtime/${encodeURIComponent(btn.dataset.rtRestart)}/restart${q}`, {});
          if (status) status.textContent = r.message || 'Restarted';
          await refreshRuntime();
        } catch (err) {
          if (status) status.textContent = err.message;
        }
      });
    });

    const running = slots.filter((s) => s.running).length;
    if (status)
      status.textContent = `${running} running · ${slots.length} slots · ${data?.machineName || 'local'}`;
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="hint">${escapeAttr(err.message)}</td></tr>`;
    if (status) status.textContent = err.message;
  }
}

document.getElementById('labs-refresh')?.addEventListener('click', () => {
  persistLabsAgentUrl();
  refreshLabs().catch(() => {});
});
document.getElementById('labs-category-filter')?.addEventListener('change', () => {
  refreshLabs().catch(() => {});
});
document.getElementById('runtime-refresh')?.addEventListener('click', () => {
  persistLabsAgentUrl();
  refreshRuntime().catch(() => {});
});
document.getElementById('runtime-stop-all')?.addEventListener('click', async () => {
  const status = document.getElementById('runtime-status');
  persistLabsAgentUrl();
  if (status) status.textContent = 'Stopping all runtime slots…';
  try {
    const r = await api.post(`/api/runtime/stop-all${labsAgentQuery()}`, {});
    if (status) status.textContent = r.message || 'Stopped all';
    await refreshRuntime();
  } catch (err) {
    if (status) status.textContent = err.message;
  }
});
document.getElementById('labs-stop-all')?.addEventListener('click', async () => {
  const status = document.getElementById('labs-status');
  persistLabsAgentUrl();
  if (status) status.textContent = 'Stopping all labs…';
  try {
    const r = await api.post(`/api/labs/stop-all${labsAgentQuery()}`, {});
    if (status) status.textContent = r.message || 'Stopped all';
    await refreshLabs();
  } catch (err) {
    if (status) status.textContent = err.message;
  }
});
document.getElementById('labs-agent-ping')?.addEventListener('click', async () => {
  const status = document.getElementById('labs-status');
  const hint = document.getElementById('labs-agent-hint');
  persistLabsAgentUrl();
  try {
    const ping = await api.get(`/api/labs/ping${labsAgentQuery()}`);
    const msg = ping.ok
      ? `Agent OK · ${ping.appName || 'Randfuzz'} ${ping.version || ''} @ ${ping.agentUrl}`
      : 'Agent ping failed';
    if (status) status.textContent = msg;
    if (hint) hint.textContent = msg;
    await refreshLabs();
  } catch (err) {
    if (status) status.textContent = err.message;
    if (hint) hint.textContent = err.message;
  }
});
document.getElementById('labs-agent-clear')?.addEventListener('click', () => {
  const input = document.getElementById('labs-agent-url');
  const tok = document.getElementById('labs-agent-token');
  if (input) input.value = '';
  if (tok) tok.value = '';
  persistLabsAgentUrl();
  refreshLabs().catch(() => {});
});
document.getElementById('labs-agent-url')?.addEventListener('change', () => {
  persistLabsAgentUrl();
  refreshLabs().catch(() => {});
});
document.getElementById('labs-agent-token')?.addEventListener('change', () => {
  persistLabsAgentUrl();
});

let caseOpsBound = false;

async function loadCaseBuilder() {
  caseOps = await api.get('/api/case/ops');
  const buttons = document.getElementById('case-op-buttons');
  buttons.innerHTML = caseOps.map((op) =>
    `<button type="button" class="btn" data-op="${op.id}" title="${op.description}">+ ${op.name}</button>`).join('');
  if (!caseOpsBound) {
    buttons.addEventListener('click', (ev) => {
      const b = ev.target.closest('button[data-op]');
      if (!b) return;
      caseSteps.push(defaultStep(b.dataset.op));
      renderCaseSteps();
    });
    caseOpsBound = true;
  }
  // Prefer the Campaign Target profile's project name when opening Case builder
  const fuzzSel = document.getElementById('fuzz-target');
  const caseSel = document.getElementById('case-project');
  const fuzzName = fuzzSel?.selectedOptions?.[0]?.dataset?.name;
  if (fuzzName && caseSel && [...caseSel.options].some((o) => o.value === fuzzName))
    caseSel.value = fuzzName;
  await refreshCaseProject();
  await refreshCasePacks();
  await loadRecipeCatalog();
  renderCaseSteps();
}

async function refreshCasePacks() {
  const sel = document.getElementById('case-pack-select');
  if (!sel) return;
  try {
    const packs = await api.get('/api/case/packs');
    const cur = sel.value;
    sel.innerHTML = '<option value="">— load a pack —</option>' +
      (packs || []).map((p) =>
        `<option value="${escapeAttr(p.id)}">${escapeAttr(p.name)}${p.sessionStepCount ? ` (${p.sessionStepCount} PDUs)` : ''}</option>`
      ).join('');
    if (cur && [...sel.options].some((o) => o.value === cur)) sel.value = cur;
  } catch {
    sel.innerHTML = '<option value="">(packs unavailable)</option>';
  }
}

function defaultStep(op) {
  const base = { op, value: '', count: 16, format: 'u32le', role: 'fuzzable' };
  if (op === 'static') return { ...base, value: 'GET', role: 'static' };
  if (op === 'text') return { ...base, value: 'index.html', role: 'fuzzable' };
  if (op === 'delim') return { ...base, value: ' ', role: 'fuzzable' };
  if (op === 'hex') return { ...base, value: '00 ff' };
  if (op === 'repeat') return { ...base, value: 'A', count: 100 };
  if (op === 'fill') return { ...base, value: '0x00', count: 16 };
  if (op === 'pad') return { ...base, value: '0x00', count: 16 };
  if (op === 'crlf' || op === 'lf' || op === 'null') return { ...base, value: '' };
  if (op === 'cyclic') return { ...base, count: 200 };
  if (op === 'len-prefix') return { ...base, format: 'u16le' };
  if (op === 'interesting') return { ...base, format: 'u32le', value: '' };
  if (op === 'base64') return { ...base, value: '' };
  if (op === 'utf16') return { ...base, value: 'wide', role: 'fuzzable' };
  if (op === 'quote') return { ...base, value: 'arg', role: 'fuzzable' };
  if (op === 'random') return { ...base, count: 32 };
  return base;
}

function flattenCaseLayers(layers) {
  return (layers || []).flatMap((l) => mapApiSteps(l.blocks || []));
}

function flushActiveLayer() {
  if (!caseLayers || !caseLayers[caseActiveLayer]) return;
  caseLayers[caseActiveLayer].blocks = mapApiSteps(collectCaseSteps());
}

function renderCaseLayers() {
  const el = document.getElementById('case-layers');
  if (!el) return;
  if (!caseLayers || !caseLayers.length) {
    el.innerHTML = '<p class="hint">Single flat PDU — add a layer or load a stack template.</p>';
    return;
  }
  el.innerHTML = caseLayers.map((l, i) =>
    `<div class="case-layer ${i === caseActiveLayer ? 'active' : ''}">
      <button type="button" class="btn ${i === caseActiveLayer ? 'primary' : ''}" data-layer-go="${i}">${i}</button>
      <input type="text" data-layer-name="${i}" value="${escapeAttr(l.name)}" title="Layer name" />
      <button type="button" class="btn" data-layer-del="${i}" title="Remove layer" ${caseLayers.length <= 1 ? 'disabled' : ''}>×</button>
    </div>`).join('');
  el.querySelectorAll('[data-layer-go]').forEach((btn) => {
    btn.addEventListener('click', () => {
      flushActiveLayer();
      caseActiveLayer = Number(btn.dataset.layerGo);
      caseSteps = mapApiSteps(caseLayers[caseActiveLayer].blocks);
      renderCaseLayers();
      renderCaseSteps();
    });
  });
  el.querySelectorAll('[data-layer-name]').forEach((inp) => {
    inp.addEventListener('change', () => {
      const i = Number(inp.dataset.layerName);
      if (caseLayers[i]) caseLayers[i].name = inp.value.trim() || `layer${i + 1}`;
    });
  });
  el.querySelectorAll('[data-layer-del]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const i = Number(btn.dataset.layerDel);
      if (caseLayers.length <= 1) return;
      flushActiveLayer();
      caseLayers.splice(i, 1);
      caseActiveLayer = Math.min(caseActiveLayer, caseLayers.length - 1);
      caseSteps = mapApiSteps(caseLayers[caseActiveLayer].blocks);
      renderCaseLayers();
      renderCaseSteps();
    });
  });
}

function renderCaseFieldTable() {
  const el = document.getElementById('case-field-table');
  const on = !!document.getElementById('case-field-table-toggle')?.checked;
  if (!el) return;
  el.classList.toggle('hidden', !on);
  if (!on) return;
  const rows = caseSteps.map((s, i) =>
    `<tr>
      <td>${i}</td>
      <td>${escapeAttr(s.op)}</td>
      <td>${escapeAttr(s.format || '')}</td>
      <td>${escapeAttr(s.role || '')}</td>
      <td><code>${escapeAttr((s.value || '').toString().slice(0, 48))}</code></td>
    </tr>`).join('');
  el.innerHTML = `<table><thead><tr><th>#</th><th>op</th><th>type/endian</th><th>fuzzable</th><th>value</th></tr></thead><tbody>${rows || '<tr><td colspan="5">No blocks</td></tr>'}</tbody></table>`;
}

function applyLayerStackTemplate(layers, statusMsg) {
  caseLayers = layers.map((l) => ({
    name: l.name,
    blocks: mapApiSteps(l.blocks),
  }));
  caseActiveLayer = Math.max(0, caseLayers.length - 1);
  caseSteps = mapApiSteps(caseLayers[caseActiveLayer].blocks);
  if (isCaseSessionMode() && caseSessionSteps[caseActivePdu]) {
    caseSessionSteps[caseActivePdu].layers = caseLayers;
    caseSessionSteps[caseActivePdu].blocks = flattenCaseLayers(caseLayers);
  }
  renderCaseLayers();
  renderCaseSteps();
  document.getElementById('case-save-result').textContent = statusMsg;
}

function renderCaseSteps() {
  const el = document.getElementById('case-steps');
  if (!caseSteps.length) {
    el.innerHTML = '<p class="hint">No blocks yet — click an op on the left, or use a preset.</p>';
    renderCaseFieldTable();
    return;
  }
  el.innerHTML = caseSteps.map((s, i) => {
    const opMeta = caseOps.find((o) => o.id === s.op);
    const fields = opMeta?.fields || [];
    return `<div class="case-step" data-i="${i}">
      <div class="case-step-head">
        <strong>${s.op}</strong>
        <span>
          <button type="button" class="btn" data-up="${i}">↑</button>
          <button type="button" class="btn" data-down="${i}">↓</button>
          <button type="button" class="btn" data-del="${i}">×</button>
        </span>
      </div>
      ${fields.includes('value') ? `<input data-field="value" data-i="${i}" value="${escapeAttr(s.value || '')}" placeholder="value" />` : ''}
      <div class="mini-row">
        ${fields.includes('count') ? `<input type="number" data-field="count" data-i="${i}" value="${s.count ?? 16}" placeholder="count" />` : ''}
        ${fields.includes('format') ? `<input data-field="format" data-i="${i}" value="${escapeAttr(s.format || '')}" placeholder="format e.g. u16le" />` : ''}
        ${fields.includes('role') ? `<select data-field="role" data-i="${i}">
          <option value="static" ${s.role === 'static' ? 'selected' : ''}>static (s_static)</option>
          <option value="fuzzable" ${s.role !== 'static' ? 'selected' : ''}>fuzzable (s_string/delim)</option>
        </select>` : ''}
      </div>
    </div>`;
  }).join('');

  el.querySelectorAll('[data-del]').forEach((b) => b.addEventListener('click', () => {
    caseSteps.splice(Number(b.dataset.del), 1);
    renderCaseSteps();
  }));
  el.querySelectorAll('[data-up]').forEach((b) => b.addEventListener('click', () => {
    const i = Number(b.dataset.up);
    if (i <= 0) return;
    [caseSteps[i - 1], caseSteps[i]] = [caseSteps[i], caseSteps[i - 1]];
    renderCaseSteps();
  }));
  el.querySelectorAll('[data-down]').forEach((b) => b.addEventListener('click', () => {
    const i = Number(b.dataset.down);
    if (i >= caseSteps.length - 1) return;
    [caseSteps[i + 1], caseSteps[i]] = [caseSteps[i], caseSteps[i + 1]];
    renderCaseSteps();
  }));
  el.querySelectorAll('[data-field]').forEach((inp) => {
    inp.addEventListener('change', () => {
      const i = Number(inp.dataset.i);
      const field = inp.dataset.field;
      caseSteps[i][field] = field === 'count' ? Number(inp.value) : inp.value;
      renderCaseFieldTable();
    });
  });
  renderCaseFieldTable();
}

function escapeAttr(s) {
  return String(s ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;');
}

function collectCaseSteps() {
  document.querySelectorAll('#case-steps [data-field]').forEach((inp) => {
    const i = Number(inp.dataset.i);
    const field = inp.dataset.field;
    if (!caseSteps[i]) return;
    caseSteps[i][field] = field === 'count' ? Number(inp.value) : inp.value;
  });
  return caseSteps.map((s) => ({
    op: s.op,
    value: s.value || null,
    count: s.count ?? null,
    format: s.format || null,
    role: s.role || 'fuzzable',
  }));
}

function isCaseSessionMode() {
  return Array.isArray(caseSessionSteps) && caseSessionSteps.length > 0;
}

function mapBlocksForApi(blocks) {
  return (blocks || []).map((s) => ({
    op: s.op,
    value: s.value || null,
    count: s.count ?? null,
    format: s.format || null,
    role: s.role || 'fuzzable',
  }));
}

function flushActiveSessionPdu() {
  if (!isCaseSessionMode() || !caseSessionSteps[caseActivePdu]) return;
  flushActiveLayer();
  if (caseLayers && caseLayers.length) {
    caseSessionSteps[caseActivePdu].layers = caseLayers.map((l) => ({
      name: l.name,
      blocks: mapBlocksForApi(l.blocks),
    }));
    caseSessionSteps[caseActivePdu].blocks = flattenCaseLayers(caseLayers);
  } else {
    caseSessionSteps[caseActivePdu].blocks = mapApiSteps(collectCaseSteps());
    caseSessionSteps[caseActivePdu].layers = null;
  }
  const nameInp = document.querySelector(`#case-session-steps [data-pdu-name="${caseActivePdu}"]`);
  if (nameInp) caseSessionSteps[caseActivePdu].name = nameInp.value.trim() || `PDU${caseActivePdu + 1}`;
  const ban = document.querySelector(`#case-session-steps [data-pdu-banner="${caseActivePdu}"]`);
  if (ban) caseSessionSteps[caseActivePdu].readBanner = !!ban.checked;
  const exp = document.querySelector(`#case-session-steps [data-pdu-expect="${caseActivePdu}"]`);
  if (exp) caseSessionSteps[caseActivePdu].expectResponse = exp.value.trim();
}

function collectSessionStepsPayload() {
  flushActiveSessionPdu();
  return caseSessionSteps.map((s) => ({
    name: s.name || 'PDU',
    readBanner: !!s.readBanner,
    expectResponse: s.expectResponse || null,
    blocks: mapBlocksForApi(s.blocks),
    layers: (s.layers && s.layers.length)
      ? s.layers.map((l) => ({ name: l.name, blocks: mapBlocksForApi(l.blocks) }))
      : null,
  }));
}

function ensureCaseSessionMode() {
  if (isCaseSessionMode()) return;
  caseSessionSteps = [{
    name: 'PDU1',
    readBanner: true,
    expectResponse: '',
    blocks: mapApiSteps(collectCaseSteps()),
  }];
  caseActivePdu = 0;
}

function setActivePdu(index) {
  if (!isCaseSessionMode()) return;
  flushActiveSessionPdu();
  caseActivePdu = Math.max(0, Math.min(index, caseSessionSteps.length - 1));
  const pdu = caseSessionSteps[caseActivePdu];
  if (pdu.layers && pdu.layers.length) {
    caseLayers = pdu.layers.map((l) => ({
      name: l.name || 'layer',
      blocks: mapApiSteps(l.blocks || []),
    }));
    caseActiveLayer = Math.max(0, caseLayers.length - 1);
    caseSteps = mapApiSteps(caseLayers[caseActiveLayer].blocks);
  } else {
    caseLayers = [{ name: 'pdu', blocks: mapApiSteps(pdu.blocks || []) }];
    caseActiveLayer = 0;
    caseSteps = mapApiSteps(pdu.blocks || []);
  }
  renderCaseSessionSteps();
  renderCaseLayers();
  renderCaseSteps();
  const label = document.getElementById('case-active-pdu-label');
  if (label) label.textContent = `— editing ${caseSessionSteps[caseActivePdu].name}`;
}

function syncCaseSessionPanel() {
  const kind = (caseProfile?.kind || '').toLowerCase();
  const panel = document.getElementById('case-session-panel');
  const body = document.getElementById('case-session-body');
  const hint = document.getElementById('case-session-hint');
  const badge = document.getElementById('case-session-badge');
  const unlocked = kind === 'tcp' || kind === 'udp';
  panel?.classList.toggle('case-session-locked', !unlocked);
  panel?.classList.toggle('case-session-ready', unlocked);
  if (body) body.classList.toggle('hidden', !unlocked);
  if (badge) {
    badge.textContent = kind === 'tcp'
      ? 'TCP ready'
      : kind === 'udp'
        ? 'UDP datagram'
        : (kind ? `${kind} — switch to TCP/UDP` : 'TCP / UDP');
    badge.classList.toggle('ok', unlocked);
  }
  if (hint) {
    if (kind === 'tcp') {
      hint.innerHTML =
        'Multi-message TCP on one connection — each PDU has its own blocks. Use <strong>+ PDU</strong>, load a <em>protocol pack</em>, then <strong>Apply to Campaign</strong>.';
    } else if (kind === 'udp') {
      hint.innerHTML =
        'UDP single-datagram mode — load pack <code>dns-query</code> (or one PDU), then <strong>Apply to Campaign</strong> (writes <code>sessionCommands</code> only).';
    } else {
      hint.innerHTML =
        `Network session needs a <em>TCP</em> or <em>UDP</em> Target profile. You are on <strong>${escapeAttr(caseProfile?.project || kind || '—')} [${escapeAttr(kind || '?')}]</strong>.
         In Step 1: create <strong>TCP/UDP network</strong> → Create target, or change <em>Working on project</em>.`;
    }
  }
  if (!unlocked) {
    caseSessionSteps = null;
    caseActivePdu = 0;
    const label = document.getElementById('case-active-pdu-label');
    if (label) label.textContent = '';
  }
  renderCaseSessionSteps();
}

function focusCaseSessionPanel() {
  const panel = document.getElementById('case-session-panel');
  if (!panel) return;
  panel.classList.add('case-session-flash');
  panel.scrollIntoView({ behavior: 'smooth', block: 'center' });
  setTimeout(() => panel.classList.remove('case-session-flash'), 1600);
}

function renderCaseSessionSteps() {
  const el = document.getElementById('case-session-steps');
  if (!el) return;
  if (!isCaseSessionMode()) {
    el.innerHTML = '<p class="hint">Single-blob recipe (default). Click <strong>+ PDU</strong> or load <em>FTP login flow</em> for multi-message TCP.</p>';
    return;
  }
  el.innerHTML = caseSessionSteps.map((s, i) =>
    `<div class="case-pdu ${i === caseActivePdu ? 'active' : ''}" data-pdu="${i}">
      <button type="button" class="btn case-pdu-select ${i === caseActivePdu ? 'primary' : ''}" data-pdu-go="${i}">${i}</button>
      <input type="text" data-pdu-name="${i}" value="${escapeAttr(s.name)}" title="PDU / sessionCommands name" />
      <label class="checkbox"><input type="checkbox" data-pdu-banner="${i}" ${s.readBanner ? 'checked' : ''}/> banner</label>
      <input type="text" class="case-pdu-expect" data-pdu-expect="${i}" value="${escapeAttr(s.expectResponse || '')}"
        placeholder="expect…" title="expectResponse substring (optional)" />
      <button type="button" class="btn" data-pdu-up="${i}" title="Move up" ${i === 0 ? 'disabled' : ''}>↑</button>
      <button type="button" class="btn" data-pdu-down="${i}" title="Move down" ${i >= caseSessionSteps.length - 1 ? 'disabled' : ''}>↓</button>
      <button type="button" class="btn" data-pdu-del="${i}" title="Remove PDU" ${caseSessionSteps.length <= 1 ? 'disabled' : ''}>×</button>
    </div>`).join('');

  el.querySelectorAll('[data-pdu-go]').forEach((btn) => {
    btn.addEventListener('click', () => setActivePdu(Number(btn.dataset.pduGo)));
  });
  el.querySelectorAll('[data-pdu-name]').forEach((inp) => {
    inp.addEventListener('change', () => {
      const i = Number(inp.dataset.pduName);
      if (caseSessionSteps[i]) caseSessionSteps[i].name = inp.value.trim() || `PDU${i + 1}`;
      if (i === caseActivePdu) {
        const label = document.getElementById('case-active-pdu-label');
        if (label) label.textContent = `— editing ${caseSessionSteps[i].name}`;
      }
    });
  });
  el.querySelectorAll('[data-pdu-banner]').forEach((inp) => {
    inp.addEventListener('change', () => {
      const i = Number(inp.dataset.pduBanner);
      if (caseSessionSteps[i]) caseSessionSteps[i].readBanner = !!inp.checked;
    });
  });
  el.querySelectorAll('[data-pdu-expect]').forEach((inp) => {
    inp.addEventListener('change', () => {
      const i = Number(inp.dataset.pduExpect);
      if (caseSessionSteps[i]) caseSessionSteps[i].expectResponse = inp.value.trim();
    });
  });
  el.querySelectorAll('[data-pdu-up]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const i = Number(btn.dataset.pduUp);
      if (i <= 0) return;
      flushActiveSessionPdu();
      [caseSessionSteps[i - 1], caseSessionSteps[i]] = [caseSessionSteps[i], caseSessionSteps[i - 1]];
      if (caseActivePdu === i) caseActivePdu = i - 1;
      else if (caseActivePdu === i - 1) caseActivePdu = i;
      setActivePdu(caseActivePdu);
    });
  });
  el.querySelectorAll('[data-pdu-down]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const i = Number(btn.dataset.pduDown);
      if (i >= caseSessionSteps.length - 1) return;
      flushActiveSessionPdu();
      [caseSessionSteps[i + 1], caseSessionSteps[i]] = [caseSessionSteps[i], caseSessionSteps[i + 1]];
      if (caseActivePdu === i) caseActivePdu = i + 1;
      else if (caseActivePdu === i + 1) caseActivePdu = i;
      setActivePdu(caseActivePdu);
    });
  });
  el.querySelectorAll('[data-pdu-del]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const i = Number(btn.dataset.pduDel);
      if (caseSessionSteps.length <= 1) return;
      flushActiveSessionPdu();
      caseSessionSteps.splice(i, 1);
      if (caseActivePdu >= caseSessionSteps.length) caseActivePdu = caseSessionSteps.length - 1;
      else if (caseActivePdu > i) caseActivePdu -= 1;
      setActivePdu(caseActivePdu);
    });
  });
  const label = document.getElementById('case-active-pdu-label');
  if (label) label.textContent = `— editing ${caseSessionSteps[caseActivePdu].name}`;
}

let caseProfile = null;

function syncCaseKindUi(kind) {
  const isFile = kind === 'file';
  const net = document.getElementById('case-new-network');
  const file = document.getElementById('case-new-file');
  if (net) {
    net.disabled = isFile;
    net.classList.toggle('case-fieldset-disabled', isFile);
  }
  if (file) {
    file.disabled = !isFile;
    file.classList.toggle('case-fieldset-disabled', !isFile);
  }
  const hiddenKind = document.getElementById('case-new-kind');
  if (hiddenKind) hiddenKind.value = kind;
  document.querySelectorAll('input[name="case-new-kind"]').forEach((r) => {
    r.checked = r.value === kind;
  });
  document.getElementById('case-preset-network')?.classList.toggle('hidden', isFile);
  document.getElementById('case-preset-file')?.classList.toggle('hidden', !isFile);
}

function syncCaseEditKindUi(kind) {
  const isFile = (kind || '').toLowerCase() === 'file';
  const net = document.getElementById('case-edit-network');
  if (net) {
    net.disabled = isFile;
    net.classList.toggle('case-fieldset-disabled', isFile);
  }
  const llWrap = document.getElementById('case-edit-longlived-wrap');
  if (llWrap) llWrap.classList.toggle('case-fieldset-disabled', isFile);
}

async function refreshCaseProject() {
  const name = document.getElementById('case-project')?.value;
  if (!name) return;
  const p = await api.get(`/api/case/project/${encodeURIComponent(name)}`);
  caseProfile = p;
  syncCaseSessionPanel();
  const seedNames = (p.seeds || []).map((s) => s.fileName || s).slice(0, 8);
  const kind = (p.kind || '').toLowerCase();
  document.getElementById('case-project-tip').textContent =
    `[${kind}] ${p.tip} · ${seedNames.length} seed(s)` +
    (p.configPath ? ` · ${p.configPath}` : '');
  document.getElementById('case-mutators').textContent =
    `Active: ${(p.mutators || []).join(', ') || '(none)'}`;

  const banner = document.getElementById('case-campaign-banner');
  if (banner) {
    banner.classList.remove('hidden');
    banner.innerHTML =
      `Campaign name: <strong>${escapeAttr(p.project)}</strong> — pick this under ` +
      `<em>Fuzz → Campaign → Target profile</em> after you save a seed. ` +
      (kind === 'file'
        ? 'File-format target (no host/port). Network session PDUs need a <em>TCP</em> project.'
        : kind === 'tcp'
          ? `TCP → ${escapeAttr(p.host)}:${p.port}. Scroll to <strong>Network session (PDUs)</strong> in the Recipe column.`
          : `Network ${kind.toUpperCase()} → ${escapeAttr(p.host)}:${p.port}.`);
  }

  syncCaseEditKindUi(kind);
  // Align seed presets with selected project kind
  document.getElementById('case-preset-network')?.classList.toggle('hidden', kind === 'file');
  document.getElementById('case-preset-file')?.classList.toggle('hidden', kind !== 'file');

  const desc = document.getElementById('case-edit-desc');
  const host = document.getElementById('case-edit-host');
  const port = document.getElementById('case-edit-port');
  const exe = document.getElementById('case-edit-exe');
  const ll = document.getElementById('case-edit-longlived');
  if (desc) desc.value = p.description || '';
  if (host) host.value = p.host || '';
  if (port) port.value = p.port || 0;
  if (exe) exe.value = p.executable || '';
  if (ll) ll.checked = !!p.longLived;
  const dictEl = document.getElementById('case-dict-sample');
  if (dictEl) {
    const sample = p.dictionarySample || [];
    dictEl.innerHTML = sample.length
      ? sample.slice(0, 12).map((t) => `<li><code>${escapeAttr(t)}</code></li>`).join('')
      : '<li class="hint">(empty — Save dict tokens from the recipe)</li>';
  }
  renderCaseMutators(p);
  renderCaseSeedList(p.seeds || []);
  await refreshCaseRecipes(name);
}

async function refreshCaseRecipes(project) {
  const el = document.getElementById('case-recipe-list');
  if (!el || !project) return;
  try {
    const list = await api.get(`/api/case/recipes/${encodeURIComponent(project)}`);
    renderCaseRecipeList(list || []);
  } catch {
    el.innerHTML = '<p class="hint">No recipes yet — Save recipe to keep an editable scare attempt.</p>';
  }
}

function mapApiSteps(steps) {
  return (steps || []).map((s) => ({
    op: s.op,
    value: s.value || '',
    count: s.count ?? 16,
    format: s.format || 'u32le',
    role: s.role || 'fuzzable',
  }));
}

function renderCaseRecipeList(recipes) {
  const el = document.getElementById('case-recipe-list');
  if (!el) return;
  if (!recipes.length) {
    el.innerHTML = '<p class="hint">No saved recipes — build blocks, name the recipe, Save recipe.</p>';
    return;
  }
  el.innerHTML = recipes.map((r) =>
    `<div class="case-recipe-row">
      <button type="button" class="btn case-recipe-btn" data-recipe="${escapeAttr(r.name)}" title="${escapeAttr(r.description || '')}">
        ${escapeAttr(r.name)} <span class="hex">${r.sessionStepCount > 0 ? `${r.sessionStepCount} PDUs · ` : ''}${r.stepCount} blocks</span>
      </button>
      <button type="button" class="btn" data-recipe-append="${escapeAttr(r.name)}" title="Append onto current recipe">Append</button>
      <button type="button" class="btn" data-recipe-del="${escapeAttr(r.name)}" title="Delete recipe">×</button>
    </div>`).join('');

  el.querySelectorAll('[data-recipe]').forEach((btn) => {
    btn.addEventListener('click', () => loadCaseRecipe(btn.dataset.recipe, false));
  });
  el.querySelectorAll('[data-recipe-append]').forEach((btn) => {
    btn.addEventListener('click', () => loadCaseRecipe(btn.dataset.recipeAppend, true));
  });
  el.querySelectorAll('[data-recipe-del]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const project = document.getElementById('case-project').value;
      if (!confirm(`Delete recipe “${btn.dataset.recipeDel}”?`)) return;
      try {
        const r = await api.del(
          `/api/case/recipes/${encodeURIComponent(project)}/${encodeURIComponent(btn.dataset.recipeDel)}`);
        document.getElementById('case-save-result').textContent = r.message || `Deleted ${btn.dataset.recipeDel}`;
        await refreshCaseRecipes(project);
      } catch (err) {
        document.getElementById('case-save-result').textContent = err.message;
      }
    });
  });
}

async function loadCaseRecipe(name, append) {
  const project = document.getElementById('case-project').value;
  try {
    const r = await api.get(`/api/case/recipes/${encodeURIComponent(project)}/${encodeURIComponent(name)}`);
    const session = r.sessionSteps || [];
    if (!append && session.length > 0) {
      caseSessionSteps = session.map((s, i) => ({
        name: s.name || `PDU${i + 1}`,
        readBanner: !!s.readBanner,
        expectResponse: s.expectResponse || '',
        blocks: mapApiSteps(s.blocks),
      }));
      caseActivePdu = 0;
      caseSteps = mapApiSteps(caseSessionSteps[0].blocks);
      const mut = document.getElementById('case-mutate-step');
      if (mut && r.mutateStep) mut.value = r.mutateStep;
    } else {
      const mapped = mapApiSteps(r.steps);
      if (append && isCaseSessionMode()) {
        flushActiveSessionPdu();
        caseSessionSteps[caseActivePdu].blocks = [
          ...caseSessionSteps[caseActivePdu].blocks,
          ...mapped,
        ];
        caseSteps = mapApiSteps(caseSessionSteps[caseActivePdu].blocks);
      } else if (append) {
        caseSteps = [...caseSteps, ...mapped];
      } else {
        caseSessionSteps = null;
        caseSteps = mapped;
      }
    }
    const nameEl = document.getElementById('case-recipe-name');
    const descEl = document.getElementById('case-recipe-desc');
    if (nameEl && !append) nameEl.value = r.name || name;
    if (descEl && !append) descEl.value = r.description || '';
    if (r.suggestedSeedName && !append) {
      const seedEl = document.getElementById('case-seed-name');
      if (seedEl) seedEl.value = r.suggestedSeedName;
    }
    renderCaseSessionSteps();
    renderCaseSteps();
    const nBlocks = isCaseSessionMode()
      ? caseSessionSteps.reduce((n, s) => n + (s.blocks?.length || 0), 0)
      : caseSteps.length;
    document.getElementById('case-save-result').textContent = append
      ? `Appended recipe “${r.name || name}” — ${nBlocks} blocks`
      : isCaseSessionMode()
        ? `Loaded session recipe “${r.name || name}” (${caseSessionSteps.length} PDUs, ${nBlocks} blocks)`
        : `Loaded recipe “${r.name || name}” (${nBlocks} blocks)`;
    document.getElementById('case-preview')?.click();
  } catch (err) {
    document.getElementById('case-save-result').textContent = err.message;
  }
}

function renderCaseMutators(p) {
  const el = document.getElementById('case-mutator-checks');
  if (!el) return;
  const active = new Set((p.mutators || []).map((m) => m.toLowerCase()));
  const all = p.availableMutators || [];
  el.innerHTML = all.map((m) =>
    `<label class="checkbox"><input type="checkbox" data-mut="${m}" ${active.has(m) ? 'checked' : ''}/> ${m}</label>`
  ).join('');
}

function renderCaseSeedList(seeds) {
  const el = document.getElementById('case-seed-list');
  if (!el) return;
  if (!seeds.length) {
    el.innerHTML = '<p class="hint">No seeds yet — Preview then Save as seed.</p>';
    return;
  }
  el.innerHTML = seeds.map((s) =>
    `<button type="button" class="btn case-seed-btn" data-seed="${escapeAttr(s.fileName)}" title="${escapeAttr(s.asciiPreview || '')}">
      ${escapeAttr(s.fileName)} <span class="hex">${s.length}B</span>
    </button>`).join('');
  el.querySelectorAll('[data-seed]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const project = document.getElementById('case-project').value;
      try {
        const r = await api.get(`/api/case/load-seed/${encodeURIComponent(project)}/${encodeURIComponent(btn.dataset.seed)}`);
        caseSteps = (r.suggestedSteps || []).map((s) => ({
          op: s.op,
          value: s.value || '',
          count: s.count ?? 16,
          format: s.format || 'u32le',
          role: s.role || 'fuzzable',
        }));
        document.getElementById('case-seed-name').value = btn.dataset.seed;
        renderCaseSteps();
        document.getElementById('case-save-result').textContent =
          `Loaded ${btn.dataset.seed} (${r.length} bytes) into recipe — edit & re-save if needed.`;
      } catch (err) {
        document.getElementById('case-save-result').textContent = err.message;
      }
    });
  });
}

document.getElementById('case-project')?.addEventListener('change', () => {
  refreshCaseProject().catch(() => {});
});

/* —— Scare Floor byte editor (find/replace · invisibles · column) —— */
const caseByte = {
  mode: 'ascii', // ascii | hex
  logical: '', // editor content without invisible markers
  showInvisibles: false,
  findFrom: 0,
};

const INVIS = {
  space: '\u00B7', // ·
  tab: '\u2192', // →
  cr: '\u240D', // ␍
  lf: '\u240A', // ␊
  crlf: '\u2424', // ␤
};

function bytesFromHexFull(hex) {
  const clean = String(hex || '').replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(Math.floor(clean.length / 2));
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Latin-1 view of raw bytes (round-trip safe). Use Show invisibles for tab/space/CR/LF. */
function bytesToAsciiLogical(bytes) {
  const chunk = 0x8000;
  let s = '';
  for (let i = 0; i < bytes.length; i += chunk)
    s += String.fromCharCode(...bytes.subarray(i, Math.min(i + chunk, bytes.length)));
  return s;
}

function bytesToHexLogical(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(' ');
}

function asciiLogicalToBytes(text) {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++)
    out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

function hexLogicalToBytes(text) {
  return bytesFromHexFull(text);
}

function withInvisibles(logical) {
  let out = '';
  for (let i = 0; i < logical.length; i++) {
    const c = logical[i];
    if (c === '\r' && logical[i + 1] === '\n') {
      out += INVIS.crlf;
      i++;
    } else if (c === '\r') out += INVIS.cr;
    else if (c === '\n') out += INVIS.lf;
    else if (c === '\t') out += INVIS.tab;
    else if (c === ' ') out += INVIS.space;
    else out += c;
  }
  return out;
}

function stripInvisibles(display) {
  let out = '';
  for (let i = 0; i < display.length; i++) {
    const c = display[i];
    if (c === INVIS.crlf) out += '\r\n';
    else if (c === INVIS.cr) out += '\r';
    else if (c === INVIS.lf) out += '\n';
    else if (c === INVIS.tab) out += '\t';
    else if (c === INVIS.space) out += ' ';
    else out += c;
  }
  return out;
}

function caseByteEditorEl() {
  return document.getElementById('case-byte-editor');
}

function readCaseByteLogicalFromDom() {
  const el = caseByteEditorEl();
  if (!el) return caseByte.logical;
  const raw = el.value;
  caseByte.logical = caseByte.showInvisibles ? stripInvisibles(raw) : raw;
  return caseByte.logical;
}

function paintCaseByteEditor() {
  const el = caseByteEditorEl();
  if (!el) return;
  const start = el.selectionStart;
  const end = el.selectionEnd;
  const painted = caseByte.showInvisibles ? withInvisibles(caseByte.logical) : caseByte.logical;
  if (el.value !== painted) el.value = painted;
  el.classList.toggle('case-invis-on', caseByte.showInvisibles);
  try {
    el.setSelectionRange(Math.min(start, painted.length), Math.min(end, painted.length));
  } catch { /* ignore */ }
  document.getElementById('case-invis-legend')?.classList.toggle('hidden', !caseByte.showInvisibles);
}

function setCaseByteFromBytes(bytes) {
  caseByte.logical = caseByte.mode === 'hex'
    ? bytesToHexLogical(bytes)
    : bytesToAsciiLogical(bytes);
  paintCaseByteEditor();
}

function getCaseByteBytes() {
  const logical = readCaseByteLogicalFromDom();
  return caseByte.mode === 'hex' ? hexLogicalToBytes(logical) : asciiLogicalToBytes(logical);
}

function setCaseByteStatus(msg) {
  const el = document.getElementById('case-byte-status');
  if (el) el.textContent = msg || '';
}

function caseByteFind(nextOnly) {
  const needle = document.getElementById('case-find')?.value ?? '';
  if (!needle) {
    setCaseByteStatus('Enter find text.');
    return -1;
  }
  const logical = readCaseByteLogicalFromDom();
  const from = nextOnly ? caseByte.findFrom : 0;
  let idx = logical.indexOf(needle, from);
  if (idx < 0 && from > 0) idx = logical.indexOf(needle, 0);
  if (idx < 0) {
    setCaseByteStatus(`Not found: ${needle}`);
    return -1;
  }
  caseByte.findFrom = idx + needle.length;
  paintCaseByteEditor();
  const el = caseByteEditorEl();
  // Map logical index → display index when invisibles on
  let dStart = idx;
  let dEnd = idx + needle.length;
  if (caseByte.showInvisibles) {
    dStart = withInvisibles(logical.slice(0, idx)).length;
    dEnd = withInvisibles(logical.slice(0, idx + needle.length)).length;
  }
  el.focus();
  el.setSelectionRange(dStart, dEnd);
  setCaseByteStatus(`Found at ${idx}`);
  return idx;
}

function caseByteReplaceOne() {
  const needle = document.getElementById('case-find')?.value ?? '';
  const repl = document.getElementById('case-replace')?.value ?? '';
  if (!needle) {
    setCaseByteStatus('Enter find text.');
    return;
  }
  const logical = readCaseByteLogicalFromDom();
  let idx = -1;
  // Prefer current selection when it matches the find string
  const el = caseByteEditorEl();
  if (el && el.selectionStart !== el.selectionEnd) {
    let a = el.selectionStart;
    let b = el.selectionEnd;
    if (caseByte.showInvisibles) {
      a = stripInvisibles(el.value.slice(0, a)).length;
      b = stripInvisibles(el.value.slice(0, b)).length;
    }
    if (logical.slice(a, b) === needle) idx = a;
  }
  if (idx < 0) {
    idx = logical.indexOf(needle, caseByte.findFrom);
    if (idx < 0) idx = logical.indexOf(needle, 0);
  }
  if (idx < 0) {
    setCaseByteStatus(`Not found: ${needle}`);
    return;
  }
  caseByte.logical = logical.slice(0, idx) + repl + logical.slice(idx + needle.length);
  caseByte.findFrom = idx + repl.length;
  paintCaseByteEditor();
  const dStart = caseByte.showInvisibles
    ? withInvisibles(caseByte.logical.slice(0, idx)).length
    : idx;
  const dEnd = caseByte.showInvisibles
    ? withInvisibles(caseByte.logical.slice(0, caseByte.findFrom)).length
    : caseByte.findFrom;
  el.focus();
  el.setSelectionRange(dStart, dEnd);
  setCaseByteStatus('Replaced 1 occurrence');
}

function caseByteReplaceAll() {
  const needle = document.getElementById('case-find')?.value ?? '';
  const repl = document.getElementById('case-replace')?.value ?? '';
  if (!needle) {
    setCaseByteStatus('Enter find text.');
    return;
  }
  const logical = readCaseByteLogicalFromDom();
  if (!logical.includes(needle)) {
    setCaseByteStatus(`Not found: ${needle}`);
    return;
  }
  let count = 0;
  let i = 0;
  let out = '';
  while (i < logical.length) {
    if (logical.startsWith(needle, i)) {
      out += repl;
      i += needle.length;
      count++;
    } else {
      out += logical[i];
      i++;
    }
  }
  caseByte.logical = out;
  caseByte.findFrom = 0;
  paintCaseByteEditor();
  setCaseByteStatus(`Replaced ${count} occurrence${count === 1 ? '' : 's'}`);
}

function caseByteApplyColumn() {
  const start = Math.max(0, Number(document.getElementById('case-col-start')?.value) || 0);
  const endRaw = Number(document.getElementById('case-col-end')?.value);
  const end = Number.isFinite(endRaw) ? Math.max(start, endRaw) : start + 1;
  const value = document.getElementById('case-col-value')?.value ?? '';
  const logical = readCaseByteLogicalFromDom();
  const lines = logical.split('\n');
  const next = lines.map((line) => {
    // Preserve trailing \r if present from CRLF split oddities
    const hasCr = line.endsWith('\r');
    const body = hasCr ? line.slice(0, -1) : line;
    const left = body.slice(0, start);
    const pad = left.length < start ? ' '.repeat(start - left.length) : '';
    const right = body.slice(end);
    const mid = value;
    return left + pad + mid + right + (hasCr ? '\r' : '');
  });
  caseByte.logical = next.join('\n');
  paintCaseByteEditor();
  setCaseByteStatus(`Column ${start}–${end} applied on ${lines.length} line(s)`);
}

/** Ctrl+Alt typing: overwrite one character at the caret column on selected lines (or all lines). */
function caseByteCtrlAltInsert(ch) {
  const el = caseByteEditorEl();
  if (!el) return;
  const logical = readCaseByteLogicalFromDom();
  const lines = logical.split('\n');

  const toLogicalOffset = (domOff) =>
    (caseByte.showInvisibles ? stripInvisibles(el.value.slice(0, domOff)).length : domOff);

  const offsetToLineCol = (off) => {
    let pos = 0;
    for (let i = 0; i < lines.length; i++) {
      const bodyLen = lines[i].replace(/\r$/, '').length;
      if (off <= pos + bodyLen || i === lines.length - 1)
        return { line: i, col: Math.max(0, Math.min(off - pos, bodyLen)) };
      pos += lines[i].length + 1; // + \n
    }
    return { line: lines.length - 1, col: 0 };
  };

  const caret = offsetToLineCol(toLogicalOffset(el.selectionStart));
  const col = caret.col;
  let fromLine = 0;
  let toLine = lines.length - 1;
  if (el.selectionStart !== el.selectionEnd) {
    fromLine = offsetToLineCol(toLogicalOffset(el.selectionStart)).line;
    toLine = offsetToLineCol(toLogicalOffset(el.selectionEnd)).line;
    if (fromLine > toLine) [fromLine, toLine] = [toLine, fromLine];
  }

  const next = lines.map((line, i) => {
    if (i < fromLine || i > toLine) return line;
    const hasCr = line.endsWith('\r');
    const body = hasCr ? line.slice(0, -1) : line;
    const left = body.slice(0, col);
    const pad = left.length < col ? ' '.repeat(col - left.length) : '';
    const base = left + pad;
    return base.slice(0, col) + ch + body.slice(col + 1) + (hasCr ? '\r' : '');
  });
  caseByte.logical = next.join('\n');
  paintCaseByteEditor();
  const shown = ch === ' ' ? 'space' : ch === '\t' ? 'tab' : ch;
  setCaseByteStatus(`Ctrl+Alt: '${shown}' at column ${col} on lines ${fromLine + 1}–${toLine + 1}`);
}

function loadCaseByteEditorFromPreview(preview) {
  const bytes = bytesFromHexFull(preview.hexFull || '');
  setCaseByteFromBytes(bytes);
  document.getElementById('case-preview-ascii').textContent = preview.asciiPreview || '';
  document.getElementById('case-preview-hex').textContent = preview.hexPreview || '';
  setCaseByteStatus(`${preview.length} bytes loaded into editor (${caseByte.mode})`);
}

document.getElementById('case-preview')?.addEventListener('click', async () => {
  try {
    const preview = await api.post('/api/case/preview', { steps: collectCaseSteps() });
    document.getElementById('case-preview-meta').textContent =
      `${preview.length} bytes` + ((preview.notes || []).length ? ` — ${preview.notes.join(' ')}` : '');
    loadCaseByteEditorFromPreview(preview);
    document.getElementById('case-preview-hints').innerHTML =
      (preview.dictionaryHints || []).map((h) => `<li>${escapeAttr(h)}</li>`).join('') ||
      '<li class="hint">(none — mark text/delim as fuzzable)</li>';
  } catch (err) {
    document.getElementById('case-preview-meta').textContent = err.message;
  }
});

document.querySelectorAll('.case-byte-mode').forEach((btn) => {
  btn.addEventListener('click', () => {
    const bytes = getCaseByteBytes();
    caseByte.mode = btn.dataset.byteMode || 'ascii';
    document.querySelectorAll('.case-byte-mode').forEach((b) =>
      b.classList.toggle('active', b === btn));
    setCaseByteFromBytes(bytes);
    setCaseByteStatus(`Mode: ${caseByte.mode}`);
  });
});

document.getElementById('case-show-invisibles')?.addEventListener('change', (ev) => {
  readCaseByteLogicalFromDom();
  caseByte.showInvisibles = !!ev.target.checked;
  paintCaseByteEditor();
});

document.getElementById('case-column-mode')?.addEventListener('change', (ev) => {
  document.getElementById('case-column-row')?.classList.toggle('hidden', !ev.target.checked);
  setCaseByteStatus(ev.target.checked
    ? 'Column mode on — set cols + Apply, or Ctrl+Alt+key in the editor'
    : '');
});

document.getElementById('case-find-next')?.addEventListener('click', () => caseByteFind(true));
document.getElementById('case-replace-one')?.addEventListener('click', () => caseByteReplaceOne());
document.getElementById('case-replace-all')?.addEventListener('click', () => caseByteReplaceAll());
document.getElementById('case-col-apply')?.addEventListener('click', () => caseByteApplyColumn());

document.getElementById('case-byte-refresh')?.addEventListener('click', () => {
  document.getElementById('case-preview')?.click();
});

document.getElementById('case-byte-apply')?.addEventListener('click', () => {
  const bytes = getCaseByteBytes();
  if (!bytes.length) {
    setCaseByteStatus('Editor is empty — Preview first or type bytes.');
    return;
  }
  const hex = bytesToHexLogical(bytes);
  caseSteps = [{ op: 'hex', value: hex, role: 'fuzzable' }];
  if (isCaseSessionMode() && caseSessionSteps[caseActivePdu]) {
    caseSessionSteps[caseActivePdu].blocks = mapApiSteps(caseSteps);
    renderCaseSessionSteps();
  }
  renderCaseSteps();
  setCaseByteStatus(
    isCaseSessionMode()
      ? `Applied ${bytes.length} bytes → PDU ${caseSessionSteps[caseActivePdu].name}`
      : `Applied ${bytes.length} bytes → recipe (one hex block). Preview again to verify.`);
});

caseByteEditorEl()?.addEventListener('input', () => {
  readCaseByteLogicalFromDom();
});

caseByteEditorEl()?.addEventListener('keydown', (ev) => {
  if (ev.key === 'F3') {
    ev.preventDefault();
    caseByteFind(true);
    return;
  }
  if (ev.ctrlKey && !ev.altKey && (ev.key === 'h' || ev.key === 'H')) {
    ev.preventDefault();
    document.getElementById('case-find')?.focus();
    return;
  }
  if (ev.ctrlKey && !ev.altKey && (ev.key === 'f' || ev.key === 'F')) {
    ev.preventDefault();
    document.getElementById('case-find')?.focus();
    return;
  }
  // Ctrl+Alt + printable → column write (Notepad++-style multi-line edit)
  if (ev.ctrlKey && ev.altKey && ev.key.length === 1 && !ev.metaKey) {
    ev.preventDefault();
    caseByteCtrlAltInsert(ev.key);
  }
});

document.getElementById('case-save-seed')?.addEventListener('click', async () => {
  const project = document.getElementById('case-project').value;
  const fileName = document.getElementById('case-seed-name').value.trim() || undefined;
  try {
    const r = await api.post('/api/case/save-seed', {
      project,
      fileName,
      steps: collectCaseSteps(),
      alsoAddDictionaryHints: true,
    });
    document.getElementById('case-save-result').textContent =
      `${r.message} — next: Campaign tab → Target profile “${project}” → Start.`;
    await refreshCaseProject();
  } catch (err) {
    document.getElementById('case-save-result').textContent = err.message;
  }
});

document.getElementById('case-save-dict')?.addEventListener('click', async () => {
  const project = document.getElementById('case-project').value;
  try {
    const preview = await api.post('/api/case/preview', { steps: collectCaseSteps() });
    const r = await api.post('/api/case/save-dict', {
      project,
      tokens: preview.dictionaryHints || [],
      appendToFile: true,
    });
    document.getElementById('case-save-result').textContent = r.message;
    await refreshCaseProject();
  } catch (err) {
    document.getElementById('case-save-result').textContent = err.message;
  }
});

document.getElementById('case-save-mutators')?.addEventListener('click', async () => {
  const project = document.getElementById('case-project').value;
  const mutators = [...document.querySelectorAll('#case-mutator-checks input:checked')]
    .map((c) => c.dataset.mut);
  try {
    const r = await api.post('/api/case/mutators', { project, mutators });
    document.getElementById('case-save-result').textContent = r.message;
    await refreshCaseProject();
  } catch (err) {
    document.getElementById('case-save-result').textContent = err.message;
  }
});

document.querySelectorAll('input[name="case-new-kind"]').forEach((radio) => {
  radio.addEventListener('change', () => {
    if (radio.checked) syncCaseKindUi(radio.value);
  });
});
syncCaseKindUi(document.querySelector('input[name="case-new-kind"]:checked')?.value || 'tcp');

document.getElementById('case-new-file-format')?.addEventListener('change', () => {
  const fmt = document.getElementById('case-new-file-format').value;
  const ext = document.getElementById('case-new-ext');
  if (!ext) return;
  if (fmt === 'file-xml' && (ext.value === '.bin' || !ext.value || ext.value === '.wav')) ext.value = '.xml';
  if (fmt === 'file-wav') ext.value = '.wav';
  if (fmt === 'file-framed' || fmt === 'file-magic' || fmt === 'file-blank') {
    if (!ext.value || ext.value === '.xml' || ext.value === '.wav') ext.value = '.bin';
  }
});

document.getElementById('case-goto-campaign')?.addEventListener('click', () => {
  document.querySelector('.fuzz-subtab[data-fuzz-tab="campaign"]')?.click();
  const name = document.getElementById('case-project')?.value;
  const fuzzSel = document.getElementById('fuzz-target');
  if (name && fuzzSel) {
    const opt = [...fuzzSel.options].find((o) => o.dataset.name === name);
    if (opt) {
      fuzzSel.value = opt.value;
      refreshFuzzTargetTip().catch(() => {});
    }
  }
});

document.getElementById('case-new-create')?.addEventListener('click', async () => {
  const name = document.getElementById('case-new-name').value.trim();
  const resultEl = document.getElementById('case-create-result') || document.getElementById('case-save-result');
  if (!name) {
    resultEl.textContent = 'Enter a name — this becomes the Target profile / campaign label.';
    return;
  }
  const kind = document.querySelector('input[name="case-new-kind"]:checked')?.value
    || document.getElementById('case-new-kind').value;
  const isFile = kind === 'file';
  const exeNet = document.getElementById('case-new-exe-net')?.value?.trim();
  const exeFile = document.getElementById('case-new-exe')?.value?.trim();
  try {
    const r = await api.post('/api/case/new-project', {
      name,
      kind,
      host: isFile ? null : document.getElementById('case-new-host').value,
      port: isFile ? null : (Number(document.getElementById('case-new-port').value) || 8080),
      executable: isFile ? (exeFile || null) : (exeNet || null),
      description: document.getElementById('case-new-desc').value || null,
      localFolder: document.getElementById('case-new-local').checked,
      extension: isFile ? document.getElementById('case-new-ext')?.value : null,
      fileFormat: isFile ? document.getElementById('case-new-file-format')?.value : null,
    });
    resultEl.textContent = r.message;
    document.getElementById('case-save-result').textContent = r.message;
    const targets = await loadTargets();
    const caseSel = document.getElementById('case-project');
    const sanitized = name.trim().toLowerCase().replace(/[^a-z0-9_\-]+/g, '-').replace(/^-|-$/g, '');
    // Prefer path basename, then sanitized name, then match from /api/targets
    let pick = sanitized;
    if (r.path) {
      const base = String(r.path).replace(/\\/g, '/').split('/').pop()?.replace(/\.ya?ml$/i, '');
      if (base) pick = base;
    }
    if (caseSel) {
      const names = new Set(targets.map((t) => t.name));
      if (!names.has(pick) && names.has(sanitized)) pick = sanitized;
      if (names.has(pick)) caseSel.value = pick;
      else if (caseSel.options.length) {
        // last resort: option whose label starts with sanitized
        const opt = [...caseSel.options].find((o) => o.value === sanitized || o.textContent.startsWith(sanitized));
        if (opt) caseSel.value = opt.value;
      }
    }
    await refreshCaseProject();
    // Collapse create form so Recipe / Network session is visible
    const createDetails = document.getElementById('case-create-details');
    if (createDetails) createDetails.open = false;

    if (isFile) {
      const fmt = document.getElementById('case-new-file-format')?.value;
      if (fmt === 'file-xml') document.getElementById('case-preset-xml')?.click();
      else if (fmt === 'file-framed') document.getElementById('case-preset-file-framed')?.click();
      else if (fmt === 'file-magic') document.getElementById('case-preset-file-magic')?.click();
      else if (fmt === 'file-wav') document.getElementById('case-preset-wav')?.click();
      else document.getElementById('case-preset-file-blank')?.click();
    } else if (kind === 'tcp') {
      document.getElementById('case-save-result').textContent =
        `${r.message} — Network session (PDUs) is unlocked below. Try FTP login flow.`;
      focusCaseSessionPanel();
    }
  } catch (err) {
    resultEl.textContent = err.message;
  }
});

document.getElementById('case-edit-save')?.addEventListener('click', async () => {
  const project = document.getElementById('case-project').value;
  const isFile = (caseProfile?.kind || '').toLowerCase() === 'file';
  try {
    const body = {
      project,
      description: document.getElementById('case-edit-desc').value,
      executable: document.getElementById('case-edit-exe').value,
      longLived: isFile ? false : document.getElementById('case-edit-longlived').checked,
    };
    if (!isFile) {
      body.host = document.getElementById('case-edit-host').value;
      body.port = Number(document.getElementById('case-edit-port').value) || undefined;
    }
    const r = await api.post('/api/case/update-project', body);
    document.getElementById('case-save-result').textContent = r.message;
    await loadTargets();
    await refreshCaseProject();
    await refreshFuzzTargetTip();
  } catch (err) {
    document.getElementById('case-save-result').textContent = err.message;
  }
});

/** Last uploaded sample (base64) — for “Save exact sample”. */
let caseUploadRaw = null;

function applyCaseImportResult(r, sourceLabel) {
  caseSteps = (r.suggestedSteps || []).map((s) => ({
    op: s.op,
    value: s.value || '',
    count: s.count ?? 16,
    format: s.format || 'u32le',
    role: s.role || 'fuzzable',
  }));
  renderCaseSteps();
  if (r.suggestedSeedName) {
    const nameEl = document.getElementById('case-seed-name');
    if (nameEl) nameEl.value = r.suggestedSeedName;
  }
  const notes = (r.notes || []).join(' ');
  const msg =
    `${sourceLabel}: ${r.length} bytes → ${caseSteps.length} block(s)` +
    (r.detectedFormat ? ` · ${r.detectedFormat}` : '') +
    (notes ? ` — ${notes}` : '');
  const saveEl = document.getElementById('case-save-result');
  if (saveEl) saveEl.textContent = msg;
  const up = document.getElementById('case-upload-status');
  if (up) up.textContent = msg;
  // Auto-preview so the template is visible immediately
  document.getElementById('case-preview')?.click();
}

async function importCaseBytes(asHex) {
  const raw = document.getElementById('case-import-text').value;
  if (!raw.trim()) return;
  caseUploadRaw = null;
  document.getElementById('case-save-exact').disabled = true;
  try {
    const body = asHex ? { hex: raw } : { text: raw };
    const r = await api.post('/api/case/import', body);
    applyCaseImportResult(r, 'Imported');
  } catch (err) {
    document.getElementById('case-save-result').textContent = err.message;
  }
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = String(reader.result || '');
      const i = dataUrl.indexOf('base64,');
      resolve(i >= 0 ? dataUrl.slice(i + 7) : dataUrl);
    };
    reader.onerror = () => reject(reader.error || new Error('Failed to read file'));
    reader.readAsDataURL(file);
  });
}

async function importCaseFile(file) {
  if (!file) return;
  const status = document.getElementById('case-upload-status');
  const exactBtn = document.getElementById('case-save-exact');
  if (status) status.textContent = `Reading ${file.name} (${file.size} bytes)…`;
  try {
    const base64 = await fileToBase64(file);
    caseUploadRaw = { fileName: file.name, base64, size: file.size };
    if (exactBtn) exactBtn.disabled = false;
    const r = await api.post('/api/case/import', { base64, fileName: file.name });
    applyCaseImportResult(r, `Template from ${file.name}`);
  } catch (err) {
    if (status) status.textContent = err.message;
    document.getElementById('case-save-result').textContent = err.message;
    caseUploadRaw = null;
    if (exactBtn) exactBtn.disabled = true;
  }
}

document.getElementById('case-save-recipe')?.addEventListener('click', async () => {
  const project = document.getElementById('case-project')?.value;
  if (!project) {
    document.getElementById('case-save-result').textContent = 'Pick a Target profile first (Step 1).';
    return;
  }
  const name = document.getElementById('case-recipe-name')?.value?.trim();
  if (!name) {
    document.getElementById('case-save-result').textContent = 'Enter a recipe name (e.g. overflow-trun).';
    return;
  }
  const sessionSteps = isCaseSessionMode() ? collectSessionStepsPayload() : null;
  const steps = sessionSteps
    ? sessionSteps.flatMap((s) => s.blocks)
    : collectCaseSteps();
  if (!steps.length) {
    document.getElementById('case-save-result').textContent = 'Recipe is empty — add blocks first.';
    return;
  }
  try {
    const r = await api.post('/api/case/recipes', {
      project,
      name,
      description: document.getElementById('case-recipe-desc')?.value?.trim() || null,
      suggestedSeedName: document.getElementById('case-seed-name')?.value?.trim() || null,
      steps,
      sessionSteps,
      mutateStep: sessionSteps ? (document.getElementById('case-mutate-step')?.value || 'last') : null,
      kind: sessionSteps ? 'session' : 'blob',
    });
    document.getElementById('case-save-result').textContent = r.message;
    await refreshCaseRecipes(project);
  } catch (err) {
    document.getElementById('case-save-result').textContent = err.message;
  }
});

document.getElementById('case-pdu-add')?.addEventListener('click', () => {
  ensureCaseSessionMode();
  flushActiveSessionPdu();
  if ((caseProfile?.kind || '').toLowerCase() === 'udp' && caseSessionSteps.length >= 1) {
    document.getElementById('case-save-result').textContent =
      'UDP Apply allows one datagram PDU — remove extras or switch to a TCP project for multi-PDU flows.';
    return;
  }
  const n = caseSessionSteps.length + 1;
  caseSessionSteps.push({
    name: `PDU${n}`,
    readBanner: false,
    expectResponse: '',
    blocks: [{ op: 'text', value: 'payload', count: 16, format: 'u32le', role: 'fuzzable' }],
  });
  setActivePdu(caseSessionSteps.length - 1);
  document.getElementById('case-save-result').textContent =
    `Added ${caseSessionSteps[caseActivePdu].name} — edit its blocks below.`;
});

document.getElementById('case-preview-session')?.addEventListener('click', async () => {
  if (!isCaseSessionMode()) {
    document.getElementById('case-preview')?.click();
    return;
  }
  try {
    const preview = await api.post('/api/case/preview-session', {
      sessionSteps: collectSessionStepsPayload(),
    });
    const box = document.getElementById('case-session-preview');
    if (box) {
      box.innerHTML = (preview.steps || []).map((s) =>
        `<div class="case-pdu-preview">
          <strong>${escapeAttr(s.name)}</strong> <span class="hex">${s.length}B</span>
          <pre class="ascii-preview">${escapeAttr(s.asciiPreview || '')}</pre>
          <pre class="hex-preview">${escapeAttr(s.hexPreview || '')}</pre>
        </div>`).join('') || '<p class="hint">No PDUs</p>';
    }
    document.getElementById('case-preview-meta').textContent =
      `Session: ${preview.stepCount} PDUs · ${preview.totalLength} bytes` +
      ((preview.notes || []).length ? ` — ${preview.notes.join('; ')}` : '');
    // Load active PDU into byte editor
    const active = (preview.steps || [])[caseActivePdu] || (preview.steps || [])[0];
    if (active) {
      loadCaseByteEditorFromPreview({
        length: active.length,
        hexFull: active.hexFull,
        asciiPreview: active.asciiPreview,
        hexPreview: active.hexPreview,
      });
    }
    document.getElementById('case-preview-hints').innerHTML =
      (preview.dictionaryHints || []).map((h) => `<li>${escapeAttr(h)}</li>`).join('') ||
      '<li class="hint">(none)</li>';
  } catch (err) {
    document.getElementById('case-save-result').textContent = err.message;
  }
});

document.getElementById('case-apply-session')?.addEventListener('click', async () => {
  const project = document.getElementById('case-project')?.value;
  if (!project) {
    document.getElementById('case-save-result').textContent = 'Pick a Target profile first (Step 1).';
    return;
  }
  ensureCaseSessionMode();
  const sessionSteps = collectSessionStepsPayload();
  if (!sessionSteps.length) {
    document.getElementById('case-save-result').textContent = 'No PDUs to apply.';
    return;
  }
  const flowName = document.getElementById('case-recipe-name')?.value?.trim() || 'scare-flow';
  try {
    const r = await api.post('/api/case/apply-session', {
      project,
      flowName,
      sessionSteps,
      mutateStep: document.getElementById('case-mutate-step')?.value || 'last',
      sessionFlowBias: 0.5,
      preferModels: !!document.getElementById('case-prefer-models')?.checked,
    });
    document.getElementById('case-save-result').textContent = r.message;
    await refreshCaseProject();
  } catch (err) {
    document.getElementById('case-save-result').textContent = err.message;
  }
});

document.getElementById('case-promote-pdu')?.addEventListener('click', async () => {
  const project = document.getElementById('case-project')?.value;
  if (!project) {
    document.getElementById('case-save-result').textContent = 'Pick a Target profile first.';
    return;
  }
  flushActiveSessionPdu();
  const steps = collectCaseSteps();
  if (!steps.length) {
    document.getElementById('case-save-result').textContent = 'Active PDU has no blocks.';
    return;
  }
  const pduName = isCaseSessionMode()
    ? (caseSessionSteps[caseActivePdu]?.name || 'pdu')
    : (document.getElementById('case-recipe-name')?.value?.trim() || 'promoted');
  const name = `${document.getElementById('case-recipe-name')?.value?.trim() || 'scare'}_${pduName}`
    .toLowerCase().replace(/[^a-z0-9_\-]+/g, '-');
  try {
    const r = await api.post('/api/case/promote', {
      project,
      name,
      description: `Promoted from Scare Floor PDU ${pduName}`,
      sessionStepName: pduName,
      steps,
    });
    document.getElementById('case-save-result').textContent = r.message;
  } catch (err) {
    document.getElementById('case-save-result').textContent = err.message;
  }
});

document.getElementById('case-pack-load')?.addEventListener('click', async () => {
  const id = document.getElementById('case-pack-select')?.value;
  if (!id) {
    document.getElementById('case-save-result').textContent = 'Pick a protocol pack first.';
    return;
  }
  try {
    const r = await api.get(`/api/case/packs/${encodeURIComponent(id)}`);
    const session = r.sessionSteps || [];
    const kind = (caseProfile?.kind || '').toLowerCase();
    if (session.length > 0) {
      let steps = session.map((s, i) => ({
        name: s.name || `m${i + 1}`,
        readBanner: !!s.readBanner,
        expectResponse: s.expectResponse || '',
        blocks: mapApiSteps(s.blocks),
        layers: (s.layers && s.layers.length)
          ? s.layers.map((l) => ({
            name: l.name || 'layer',
            blocks: mapApiSteps(l.blocks),
          }))
          : null,
      }));
      if (kind === 'udp' && steps.length > 1) {
        steps = [steps[0]];
        document.getElementById('case-save-result').textContent =
          `Pack “${r.name || id}” has ${session.length} PDUs — UDP keeps the first datagram only.`;
      } else if (kind && kind !== 'tcp' && kind !== 'udp') {
        document.getElementById('case-save-result').textContent =
          'Pack loaded as session — switch Working on project to TCP or UDP to Apply.';
      }
      caseSessionSteps = steps;
      caseActivePdu = Math.max(0, caseSessionSteps.length - 1);
      const pdu = caseSessionSteps[caseActivePdu];
      if (pdu.layers && pdu.layers.length) {
        caseLayers = pdu.layers;
        caseActiveLayer = Math.max(0, caseLayers.length - 1);
        caseSteps = mapApiSteps(caseLayers[caseActiveLayer].blocks);
      } else {
        caseLayers = [{ name: 'pdu', blocks: mapApiSteps(pdu.blocks) }];
        caseActiveLayer = 0;
        caseSteps = mapApiSteps(pdu.blocks);
      }
      const mut = document.getElementById('case-mutate-step');
      if (mut && r.mutateStep) mut.value = r.mutateStep;
      renderCaseSessionSteps();
      renderCaseLayers();
      renderCaseSteps();
    } else {
      caseSessionSteps = null;
      caseLayers = null;
      caseSteps = mapApiSteps(r.steps);
      renderCaseSessionSteps();
      renderCaseLayers();
      renderCaseSteps();
    }
    const nameEl = document.getElementById('case-recipe-name');
    if (nameEl) nameEl.value = r.name || id;
    const descEl = document.getElementById('case-recipe-desc');
    if (descEl) descEl.value = r.description || '';
    const existing = document.getElementById('case-save-result').textContent || '';
    if (!existing.startsWith('Pack')) {
      document.getElementById('case-save-result').textContent =
        `Loaded pack “${r.name || id}”` +
        (session.length ? ` (${Math.min(session.length, caseSessionSteps?.length || session.length)} PDUs)` : ` (${caseSteps.length} blocks)`);
    }
    focusCaseSessionPanel();
  } catch (err) {
    document.getElementById('case-save-result').textContent = err.message;
  }
});

document.getElementById('case-import-hex')?.addEventListener('click', () => importCaseBytes(true));
document.getElementById('case-import-text-btn')?.addEventListener('click', () => importCaseBytes(false));

document.getElementById('case-upload-file')?.addEventListener('change', (e) => {
  const file = e.target.files?.[0];
  importCaseFile(file).catch(() => {});
  e.target.value = '';
});

document.getElementById('case-save-exact')?.addEventListener('click', async () => {
  if (!caseUploadRaw) return;
  const project = document.getElementById('case-project')?.value;
  if (!project) {
    document.getElementById('case-save-result').textContent = 'Pick a Target profile first (Step 1).';
    return;
  }
  const fileName = document.getElementById('case-seed-name')?.value?.trim() || caseUploadRaw.fileName;
  try {
    const r = await api.post('/api/case/save-raw-seed', {
      project,
      fileName,
      base64: caseUploadRaw.base64,
    });
    document.getElementById('case-save-result').textContent = r.message;
    document.getElementById('case-upload-status').textContent = r.message;
    await refreshCaseProject();
  } catch (err) {
    document.getElementById('case-save-result').textContent = err.message;
  }
});

document.getElementById('case-clear')?.addEventListener('click', () => {
  caseSteps = [];
  caseSessionSteps = null;
  caseLayers = null;
  caseActivePdu = 0;
  caseActiveLayer = 0;
  const prev = document.getElementById('case-session-preview');
  if (prev) prev.innerHTML = '';
  renderCaseSessionSteps();
  renderCaseLayers();
  renderCaseSteps();
});

document.getElementById('case-preset-http')?.addEventListener('click', () => {
  caseSteps = [
    { op: 'static', value: 'GET', role: 'static' },
    { op: 'delim', value: ' ', role: 'fuzzable' },
    { op: 'static', value: '/', role: 'static' },
    { op: 'text', value: 'index.html', role: 'fuzzable' },
    { op: 'delim', value: ' ', role: 'fuzzable' },
    { op: 'static', value: 'HTTP/1.1', role: 'static' },
    { op: 'crlf', role: 'static' },
    { op: 'static', value: 'Host: ', role: 'static' },
    { op: 'text', value: '127.0.0.1', role: 'fuzzable' },
    { op: 'crlf', role: 'static' },
    { op: 'crlf', role: 'static' },
  ];
  renderCaseSteps();
});

document.getElementById('case-preset-overflow')?.addEventListener('click', () => {
  caseSteps = [
    { op: 'static', value: 'TRUN /.:/', role: 'static' },
    { op: 'repeat', value: 'A', count: 3000, role: 'fuzzable' },
    { op: 'crlf', role: 'static' },
  ];
  renderCaseSteps();
});

document.getElementById('case-preset-binary')?.addEventListener('click', () => {
  caseSteps = [
    { op: 'hex', value: 'dead beef', role: 'static' },
    { op: 'len-prefix', format: 'u16le' },
    { op: 'text', value: 'payload', role: 'fuzzable' },
    { op: 'interesting', format: 'u32le', value: '' },
    { op: 'null' },
  ];
  renderCaseSteps();
});

document.getElementById('case-idl-import')?.addEventListener('click', async () => {
  const project = document.getElementById('case-project')?.value;
  const name = document.getElementById('case-idl-name')?.value?.trim();
  const idl = document.getElementById('case-idl-text')?.value || '';
  if (!project) {
    document.getElementById('case-save-result').textContent = 'Pick a Target profile first (Step 1).';
    return;
  }
  if (!name) {
    document.getElementById('case-save-result').textContent = 'IDL model name required.';
    return;
  }
  try {
    const r = await api.post('/api/case/idl', { project, name, idl });
    document.getElementById('case-save-result').textContent =
      r.message + (r.fields?.length ? ` · ${r.fields.join(', ')}` : '');
    await refreshCaseProject();
  } catch (err) {
    document.getElementById('case-save-result').textContent = err.message;
  }
});

document.getElementById('case-field-table-toggle')?.addEventListener('change', () => renderCaseFieldTable());

document.getElementById('case-layer-add')?.addEventListener('click', () => {
  flushActiveLayer();
  if (!caseLayers || !caseLayers.length) {
    caseLayers = [{ name: 'pdu', blocks: mapApiSteps(collectCaseSteps()) }];
  }
  caseLayers.push({
    name: `layer${caseLayers.length + 1}`,
    blocks: [{ op: 'hex', value: '00', role: 'fuzzable' }],
  });
  caseActiveLayer = caseLayers.length - 1;
  caseSteps = mapApiSteps(caseLayers[caseActiveLayer].blocks);
  renderCaseLayers();
  renderCaseSteps();
});

document.getElementById('case-layer-flatten')?.addEventListener('click', () => {
  flushActiveLayer();
  const flat = flattenCaseLayers(caseLayers || [{ name: 'pdu', blocks: caseSteps }]);
  caseLayers = [{ name: 'pdu', blocks: flat }];
  caseActiveLayer = 0;
  caseSteps = mapApiSteps(flat);
  if (isCaseSessionMode() && caseSessionSteps[caseActivePdu]) {
    caseSessionSteps[caseActivePdu].layers = null;
    caseSessionSteps[caseActivePdu].blocks = flat;
  }
  renderCaseLayers();
  renderCaseSteps();
  document.getElementById('case-save-result').textContent = `Flattened to ${flat.length} blocks.`;
});

document.getElementById('case-layer-tpl-nbss-smb2')?.addEventListener('click', () => {
  applyLayerStackTemplate([
    {
      name: 'nbss',
      blocks: [
        { op: 'hex', value: '00', role: 'static' },
        { op: 'len-prefix', format: 'nbss' },
      ],
    },
    {
      name: 'smb2',
      blocks: [
        { op: 'hex', value: 'fe 53 4d 42 40 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00', role: 'fuzzable' },
      ],
    },
  ], 'Stack template: NBSS / SMB2 — edit smb2 layer, Preview recalculates NBSS length.');
});

document.getElementById('case-layer-tpl-nbss-smb2-dce')?.addEventListener('click', () => {
  applyLayerStackTemplate([
    {
      name: 'nbss',
      blocks: [
        { op: 'hex', value: '00', role: 'static' },
        { op: 'len-prefix', format: 'nbss' },
      ],
    },
    {
      name: 'smb2',
      blocks: [
        { op: 'hex', value: 'fe 53 4d 42 40 00 01 00 00 00 00 00 09 00 01 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00', role: 'static' },
      ],
    },
    {
      name: 'dce',
      blocks: [
        { op: 'hex', value: '05 00 0b 03 10 00 00 00 48 00 00 00 01 00 00 00', role: 'fuzzable' },
      ],
    },
  ], 'Stack template: NBSS / SMB2 Write / DCE — pipe bridge shape for VulnSmb.');
});

document.getElementById('case-layer-tpl-tlv')?.addEventListener('click', () => {
  applyLayerStackTemplate([
    {
      name: 'magic',
      blocks: [{ op: 'static', value: 'CUST', role: 'static' }],
    },
    {
      name: 'len',
      blocks: [{ op: 'len-prefix', format: 'u16le' }],
    },
    {
      name: 'body',
      blocks: [{ op: 'text', value: 'payload', role: 'fuzzable' }],
    },
  ], 'Stack template: TLV (magic / len / body).');
});

document.getElementById('case-wizard-build')?.addEventListener('click', () => {
  const magic = (document.getElementById('wiz-magic')?.value || 'CUST').trim();
  const magicHex = !!document.getElementById('wiz-magic-hex')?.checked;
  const lenFmt = document.getElementById('wiz-len')?.value || 'u16le';
  const body = document.getElementById('wiz-body')?.value ?? 'payload';
  const bodyHex = !!document.getElementById('wiz-body-hex')?.checked;
  const crc = !!document.getElementById('wiz-crc')?.checked;
  const steps = [];
  if (magic) {
    steps.push(magicHex
      ? { op: 'hex', value: magic, role: 'static' }
      : { op: 'static', value: magic, role: 'static' });
  }
  if (lenFmt && lenFmt !== 'none') {
    steps.push({ op: 'len-prefix', format: lenFmt });
  }
  steps.push(bodyHex
    ? { op: 'hex', value: body || '00', role: 'fuzzable' }
    : { op: 'text', value: body, role: 'fuzzable' });
  if (crc) {
    steps.push({ op: 'crc32', format: 'u32le', role: 'static' });
  }
  caseSessionSteps = null;
  caseSteps = steps;
  renderCaseSessionSteps();
  renderCaseSteps();
  document.getElementById('case-save-result').textContent =
    `Wizard built ${steps.length} blocks` + (crc ? ' (CRC32 over preceding bytes)' : '') +
    '. Preview, Save as seed, or Promote PDU → model.';
});

document.getElementById('case-preset-dns')?.addEventListener('click', async () => {
  const sel = document.getElementById('case-pack-select');
  if (sel) {
    const opt = [...sel.options].find((o) => o.value === 'dns-query');
    if (opt) sel.value = 'dns-query';
  }
  if ((caseProfile?.kind || '').toLowerCase() !== 'udp') {
    document.getElementById('case-save-result').textContent =
      'DNS query pack works best on a UDP Target profile (e.g. dns-lab). Loading pack anyway…';
  }
  document.getElementById('case-pack-load')?.click();
});

document.getElementById('case-preset-ftp')?.addEventListener('click', () => {
  caseSessionSteps = null;
  caseSteps = [
    { op: 'static', value: 'USER', role: 'static' },
    { op: 'delim', value: ' ', role: 'fuzzable' },
    { op: 'text', value: 'anonymous', role: 'fuzzable' },
    { op: 'crlf', role: 'static' },
  ];
  renderCaseSessionSteps();
  renderCaseSteps();
});

function requireTcpForSessionPreset(label) {
  if ((caseProfile?.kind || '').toLowerCase() !== 'tcp') {
    document.getElementById('case-save-result').textContent =
      `${label} needs a TCP Target profile — create/select one in Step 1 first.`;
    focusCaseSessionPanel();
    return false;
  }
  return true;
}

function activateSessionPreset(steps, recipeName, statusMsg, activeIndex) {
  caseSessionSteps = steps;
  caseActivePdu = Math.min(activeIndex ?? steps.length - 1, steps.length - 1);
  caseLayers = [{ name: 'pdu', blocks: mapApiSteps(caseSessionSteps[caseActivePdu].blocks) }];
  caseActiveLayer = 0;
  caseSteps = mapApiSteps(caseSessionSteps[caseActivePdu].blocks);
  const nameEl = document.getElementById('case-recipe-name');
  if (nameEl && !nameEl.value) nameEl.value = recipeName;
  const mut = document.getElementById('case-mutate-step');
  if (mut) mut.value = 'last';
  renderCaseSessionSteps();
  renderCaseLayers();
  renderCaseSteps();
  document.getElementById('case-save-result').textContent = statusMsg;
  focusCaseSessionPanel();
}

function loadFtpLoginFlowPreset() {
  if (!requireTcpForSessionPreset('FTP login flow')) return;
  activateSessionPreset([
    {
      name: 'USER',
      readBanner: true,
      expectResponse: '331',
      blocks: [
        { op: 'static', value: 'USER', role: 'static' },
        { op: 'delim', value: ' ', role: 'static' },
        { op: 'text', value: 'anonymous', role: 'fuzzable' },
        { op: 'crlf', role: 'static' },
      ],
    },
    {
      name: 'PASS',
      readBanner: false,
      expectResponse: '230',
      blocks: [
        { op: 'static', value: 'PASS', role: 'static' },
        { op: 'delim', value: ' ', role: 'static' },
        { op: 'text', value: 'ftp', role: 'fuzzable' },
        { op: 'crlf', role: 'static' },
      ],
    },
    {
      name: 'STOR',
      readBanner: false,
      expectResponse: '',
      blocks: [
        { op: 'static', value: 'STOR ', role: 'static' },
        { op: 'text', value: 'file.bin', role: 'fuzzable' },
        { op: 'crlf', role: 'static' },
        { op: 'repeat', value: 'A', count: 64, role: 'fuzzable' },
      ],
    },
  ], 'ftp-login-stor', 'FTP login flow — 3 PDUs (expect 331/230). Preview → Apply to Campaign.', 2);
}

function loadSmtpSendFlowPreset() {
  if (!requireTcpForSessionPreset('SMTP send flow')) return;
  activateSessionPreset([
    {
      name: 'EHLO',
      readBanner: true,
      expectResponse: '250',
      blocks: [
        { op: 'static', value: 'EHLO ', role: 'static' },
        { op: 'text', value: 'randfuzz.local', role: 'fuzzable' },
        { op: 'crlf', role: 'static' },
      ],
    },
    {
      name: 'MAIL',
      readBanner: false,
      expectResponse: '250',
      blocks: [
        { op: 'static', value: 'MAIL FROM:<', role: 'static' },
        { op: 'text', value: 'fuzz@example.com', role: 'fuzzable' },
        { op: 'static', value: '>', role: 'static' },
        { op: 'crlf', role: 'static' },
      ],
    },
    {
      name: 'RCPT',
      readBanner: false,
      expectResponse: '250',
      blocks: [
        { op: 'static', value: 'RCPT TO:<', role: 'static' },
        { op: 'text', value: 'victim@example.com', role: 'fuzzable' },
        { op: 'static', value: '>', role: 'static' },
        { op: 'crlf', role: 'static' },
      ],
    },
    {
      name: 'DATA',
      readBanner: false,
      expectResponse: '354',
      blocks: [
        { op: 'static', value: 'DATA', role: 'static' },
        { op: 'crlf', role: 'static' },
        { op: 'static', value: 'Subject: ', role: 'static' },
        { op: 'text', value: 'randfuzz', role: 'fuzzable' },
        { op: 'crlf', role: 'static' },
        { op: 'crlf', role: 'static' },
        { op: 'text', value: 'hello', role: 'fuzzable' },
        { op: 'crlf', role: 'static' },
        { op: 'static', value: '.', role: 'static' },
        { op: 'crlf', role: 'static' },
      ],
    },
  ], 'smtp-send', 'SMTP send flow — 4 PDUs. Preview → Apply to Campaign.', 3);
}

function loadRedisRespFlowPreset() {
  if (!requireTcpForSessionPreset('Redis RESP flow')) return;
  activateSessionPreset([
    {
      name: 'AUTH',
      readBanner: false,
      expectResponse: '+OK',
      blocks: [
        { op: 'static', value: '*2', role: 'static' },
        { op: 'crlf', role: 'static' },
        { op: 'static', value: '$4', role: 'static' },
        { op: 'crlf', role: 'static' },
        { op: 'static', value: 'AUTH', role: 'static' },
        { op: 'crlf', role: 'static' },
        { op: 'static', value: '$8', role: 'static' },
        { op: 'crlf', role: 'static' },
        { op: 'text', value: 'password', role: 'fuzzable' },
        { op: 'crlf', role: 'static' },
      ],
    },
    {
      name: 'SET',
      readBanner: false,
      expectResponse: '+OK',
      blocks: [
        { op: 'static', value: '*3', role: 'static' },
        { op: 'crlf', role: 'static' },
        { op: 'static', value: '$3', role: 'static' },
        { op: 'crlf', role: 'static' },
        { op: 'static', value: 'SET', role: 'static' },
        { op: 'crlf', role: 'static' },
        { op: 'static', value: '$3', role: 'static' },
        { op: 'crlf', role: 'static' },
        { op: 'text', value: 'key', role: 'fuzzable' },
        { op: 'crlf', role: 'static' },
        { op: 'static', value: '$5', role: 'static' },
        { op: 'crlf', role: 'static' },
        { op: 'text', value: 'value', role: 'fuzzable' },
        { op: 'crlf', role: 'static' },
      ],
    },
    {
      name: 'GET',
      readBanner: false,
      expectResponse: '',
      blocks: [
        { op: 'static', value: '*2', role: 'static' },
        { op: 'crlf', role: 'static' },
        { op: 'static', value: '$3', role: 'static' },
        { op: 'crlf', role: 'static' },
        { op: 'static', value: 'GET', role: 'static' },
        { op: 'crlf', role: 'static' },
        { op: 'static', value: '$3', role: 'static' },
        { op: 'crlf', role: 'static' },
        { op: 'text', value: 'key', role: 'fuzzable' },
        { op: 'crlf', role: 'static' },
      ],
    },
  ], 'redis-resp', 'Redis RESP flow — 3 PDUs. Preview → Apply to Campaign.', 1);
}

document.getElementById('case-preset-ftp-flow')?.addEventListener('click', () => loadFtpLoginFlowPreset());
document.getElementById('case-preset-ftp-flow-inline')?.addEventListener('click', () => loadFtpLoginFlowPreset());
document.getElementById('case-preset-smtp-flow')?.addEventListener('click', () => loadSmtpSendFlowPreset());
document.getElementById('case-preset-smtp-flow-inline')?.addEventListener('click', () => loadSmtpSendFlowPreset());
document.getElementById('case-preset-redis-flow')?.addEventListener('click', () => loadRedisRespFlowPreset());
document.getElementById('case-preset-redis-flow-inline')?.addEventListener('click', () => loadRedisRespFlowPreset());

document.getElementById('case-import-session')?.addEventListener('click', async () => {
  const text = document.getElementById('case-import-text')?.value || '';
  if (!text.trim()) {
    document.getElementById('case-save-result').textContent =
      'Paste a capture first — separate PDUs with a blank line or ---';
    return;
  }
  if ((caseProfile?.kind || '').toLowerCase() !== 'tcp') {
    document.getElementById('case-save-result').textContent =
      'Import as session needs a TCP Target profile selected.';
    focusCaseSessionPanel();
    return;
  }
  try {
    const r = await api.post('/api/case/from-stream', { text, asHex: false, apply: false });
    caseSessionSteps = (r.sessionSteps || []).map((s, i) => ({
      name: s.name || `m${i + 1}`,
      readBanner: !!s.readBanner,
      expectResponse: s.expectResponse || '',
      blocks: mapApiSteps(s.blocks),
    }));
    if (!caseSessionSteps.length) {
      document.getElementById('case-save-result').textContent = 'No PDUs parsed from paste.';
      return;
    }
    caseActivePdu = 0;
    caseSteps = mapApiSteps(caseSessionSteps[0].blocks);
    const nameEl = document.getElementById('case-recipe-name');
    if (nameEl && !nameEl.value) nameEl.value = 'from-stream';
    renderCaseSessionSteps();
    renderCaseSteps();
    document.getElementById('case-save-result').textContent =
      `Imported ${caseSessionSteps.length} PDU(s) from stream` +
      ((r.notes || []).length ? ` — ${r.notes[0]}` : '') +
      '. Preview all PDUs → Apply to Campaign.';
    focusCaseSessionPanel();
  } catch (err) {
    document.getElementById('case-save-result').textContent = err.message;
  }
});

document.getElementById('case-preset-xml')?.addEventListener('click', () => {
  caseSteps = [
    { op: 'static', value: '<?xml version="1.0"?>', role: 'static' },
    { op: 'lf', role: 'static' },
    { op: 'static', value: '<root>', role: 'static' },
    { op: 'lf', role: 'static' },
    { op: 'static', value: '  <item id="', role: 'static' },
    { op: 'text', value: '1', role: 'fuzzable' },
    { op: 'static', value: '">', role: 'static' },
    { op: 'text', value: 'payload', role: 'fuzzable' },
    { op: 'static', value: '</item>', role: 'static' },
    { op: 'lf', role: 'static' },
    { op: 'static', value: '</root>', role: 'static' },
    { op: 'lf', role: 'static' },
  ];
  document.getElementById('case-seed-name').value = 'custom.xml';
  renderCaseSteps();
});

document.getElementById('case-preset-file-framed')?.addEventListener('click', () => {
  caseSteps = [
    { op: 'hex', value: 'dead beef', role: 'static' },
    { op: 'len-prefix', format: 'u16le' },
    { op: 'text', value: 'payload', role: 'fuzzable' },
    { op: 'interesting', format: 'u32le', value: '' },
  ];
  document.getElementById('case-seed-name').value = 'frame.bin';
  renderCaseSteps();
});

document.getElementById('case-preset-file-magic')?.addEventListener('click', () => {
  caseSteps = [
    { op: 'static', value: 'CUST', role: 'static' },
    { op: 'hex', value: '00 00 00 08', role: 'static' },
    { op: 'text', value: 'CUSTOM!!', role: 'fuzzable' },
    { op: 'repeat', value: 'A', count: 64, role: 'fuzzable' },
  ];
  document.getElementById('case-seed-name').value = 'magic.bin';
  renderCaseSteps();
});

document.getElementById('case-preset-file-blank')?.addEventListener('click', () => {
  caseSteps = [
    { op: 'static', value: 'RANDFUZZ_CUSTOM_SEED', role: 'static' },
    { op: 'lf', role: 'static' },
    { op: 'text', value: 'edit-me', role: 'fuzzable' },
  ];
  document.getElementById('case-seed-name').value = 'custom.bin';
  renderCaseSteps();
});

document.getElementById('case-preset-wav')?.addEventListener('click', () => {
  // Minimal PCM WAV: RIFF/WAVE + fmt (16) + data (4 silence samples)
  caseSteps = [
    { op: 'hex', value: '52 49 46 46', role: 'static' }, // RIFF
    { op: 'hex', value: '24 00 00 00', role: 'fuzzable' }, // chunk size
    { op: 'hex', value: '57 41 56 45', role: 'static' }, // WAVE
    { op: 'hex', value: '66 6D 74 20', role: 'static' }, // fmt
    { op: 'hex', value: '10 00 00 00', role: 'static' }, // fmt size
    { op: 'hex', value: '01 00 01 00 44 AC 00 00 88 58 01 00 02 00 10 00', role: 'static' },
    { op: 'hex', value: '64 61 74 61', role: 'static' }, // data
    { op: 'hex', value: '04 00 00 00', role: 'fuzzable' }, // data size
    { op: 'hex', value: '00 00 00 00', role: 'fuzzable' }, // PCM samples
  ];
  document.getElementById('case-seed-name').value = 'sample.wav';
  renderCaseSteps();
});

async function init() {
  initNavToggle();
  await initThemePicker();
  await initPlatformPicker();
  await initScreamHarvestPrefs();
  initRecipeCatalog();
  applyRemoteLabChrome();
  await loadHealth();
  refreshUpdateBanner(false).catch(() => {});
  // Background check once per session (signed manifest); major updates raise the banner.
  setTimeout(() => refreshUpdateBanner(true).catch(() => {}), 2500);
  await loadTargets();
  await loadDashboard();
  await loadStalkingView().catch(() => {});
  await loadRoadmap();
  await loadLegs();
  await loadModels();
  await loadBundlesView();
  await loadCrashes();
  await connectHub();
  await syncFuzzSession().catch(() => {});
  try {
    const savedAgent = localStorage.getItem(LABS_AGENT_KEY) || '';
    const savedTok = localStorage.getItem('randallLabsAgentToken') || '';
    const agentInput = document.getElementById('labs-agent-url');
    const tokInput = document.getElementById('labs-agent-token');
    if (agentInput && savedAgent) agentInput.value = savedAgent;
    if (tokInput && savedTok) tokInput.value = savedTok;
  } catch { /* ignore */ }
  persistLabsAgentUrl();
  refreshLabs().catch(() => {});
  setInterval(pollStatus, 3000);
  setInterval(() => refreshLabs().catch(() => {}), 4000);
  setInterval(() => {
    if (document.getElementById('view-proxy').classList.contains('visible'))
      loadProxy().catch(() => {});
  }, 4000);
}

init().catch((err) => {
  document.body.insertAdjacentHTML('beforeend', `<p class="empty">Failed to load UI: ${err.message}</p>`);
});
