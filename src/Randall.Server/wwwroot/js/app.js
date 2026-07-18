const api = {
  get: async (path) => {
    const r = await fetch(path);
    const data = await r.json().catch(() => null);
    if (!r.ok) throw new Error(data?.error || data?.message || `${r.status} ${path}`);
    return data;
  },
  post: (path, body) => fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }).then(async (r) => {
    const data = r.status === 204 ? null : await r.json().catch(() => null);
    if (!r.ok) throw new Error(data?.error || data?.message || `${r.status} ${path}`);
    return data;
  }),
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

function appendLog(line, cls = '') {
  const span = document.createElement('div');
  if (cls) span.className = cls;
  span.textContent = line;
  logEl.appendChild(span);
  logEl.scrollTop = logEl.scrollHeight;
}

function setStatus(text) {
  statusEl.textContent = text;
}

function switchView(name) {
  document.querySelectorAll('.nav-btn').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('visible', v.id === `view-${name}`));
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

async function openHelpDoc(path) {
  const doc = await api.get(`/api/docs/${path.split('/').map(encodeURIComponent).join('/')}`);
  document.getElementById('help-title').textContent = doc.title;
  const body = document.getElementById('help-content');
  const md = typeof marked !== 'undefined' ? marked.parse(doc.markdown || '') : `<pre>${escapeAttr(doc.markdown || '')}</pre>`;
  body.innerHTML = md;
  body.querySelectorAll('a[href]').forEach((a) => {
    const href = a.getAttribute('href') || '';
    if (href.endsWith('.md') && !href.startsWith('http')) {
      a.addEventListener('click', (ev) => {
        ev.preventDefault();
        openHelpDoc(href.replace(/^\.\//, '')).catch(() => {});
      });
    } else if (href.startsWith('http')) {
      a.target = '_blank';
      a.rel = 'noopener';
    }
  });
  document.querySelectorAll('.help-link').forEach((b) =>
    b.classList.toggle('active', b.dataset.doc === path));
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

async function loadHealth() {
  const h = await api.get('/api/health');
  document.getElementById('health-label').textContent = `${h.name} ${h.version} · ${h.status}`;
}

let stalkProject = null;
let stalkLiveTimeline = [];
let stalkPollTick = 0;

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
  if (s.includes('crash')) return 'status-crash';
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

function renderTimeline(points) {
  const el = document.getElementById('stalk-timeline');
  const end = document.getElementById('stalk-timeline-end');
  const list = (points || []).slice(-200);
  if (!list.length) {
    el.innerHTML = '';
    end.textContent = 'NOW';
    return;
  }
  el.innerHTML = list.map((p) => {
    const kind = p.kind || (p.crashed ? 'crash' : p.newEdges > 0 ? 'novel' : 'hit');
    const h = kind === 'crash' ? 100 : kind === 'novel' ? 70 : kind === 'miss' ? 22 : 45;
    return `<div class="bar ${kind}" style="height:${h}%" title="#${p.iteration} ${p.label || ''} (${kind})"></div>`;
  }).join('');
  const last = list[list.length - 1];
  end.textContent = last.crashed || last.kind === 'crash' ? 'NOW (CRASH)' : 'NOW';
}

function mergeTimeline(serverPoints) {
  if (!stalkLiveTimeline.length) return serverPoints || [];
  return [...(serverPoints || []), ...stalkLiveTimeline].slice(-200);
}

async function loadDashboard() {
  const targets = (await api.get('/api/targets')).filter(isVisibleTarget);
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
      stalkLiveTimeline = [];
      loadDashboard().catch(() => {});
    });
  });

  const data = await api.get(`/api/stalk/${encodeURIComponent(stalkProject)}`);
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
  renderTimeline(mergeTimeline(data.timeline));

  const log = document.getElementById('stalk-crash-log');
  if (!(data.crashLog || []).length) {
    log.innerHTML = '<p class="stalk-empty">No crashes yet — start a fuzz run from the Fuzz tab.</p>';
  } else {
    log.innerHTML = `<table><thead><tr>
      <th>ID</th><th>Sev</th><th>Class</th><th>Hits</th><th>Exception</th><th>Address</th><th>New cov</th><th>Input</th>
    </tr></thead><tbody>
      ${data.crashLog.map((c) => `<tr class="clickable crash-row" data-id="${c.id}">
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
        crashState.pendingSelectId = row.dataset.id;
        switchView('crashes');
      });
    });
  }
}

document.getElementById('stalk-refresh')?.addEventListener('click', () => loadDashboard().catch(() => {}));
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

function paintCrashInvestigate() {
  applyCrashFilters();
  renderActiveCrashFilters();
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

let hub;

async function connectHub() {
  hub = new signalR.HubConnectionBuilder().withUrl('/hubs/fuzz').withAutomaticReconnect().build();

  hub.on('fuzzStarted', (e) => {
    appendLog(`▶ Started ${e.project} (${e.kind})`);
    setStatus(`Running ${e.project}…`);
    startBtn.disabled = true;
    stalkProject = e.project || stalkProject;
    stalkLiveTimeline = [];
    if (document.getElementById('view-dashboard').classList.contains('visible'))
      loadDashboard().catch(() => {});
  });

  hub.on('fuzzIteration', (e) => {
    const cls = e.crashed ? 'crash' : e.newCoverage ? 'cov' : '';
    const tag = e.crashed ? 'CRASH' : e.newCoverage ? `+${e.newEdgeCount} edges` : 'ok';
    appendLog(`#${e.iteration} ${e.mutator} len=${e.payloadLength} ${tag}`, cls);
    setStatus(`iter ${e.iteration} · corpus ${e.corpusSize} · edges ${e.coverageEdgeTotal}`);
    stalkLiveTimeline.push({
      index: stalkLiveTimeline.length,
      kind: e.crashed ? 'crash' : e.newCoverage ? 'novel' : 'hit',
      label: e.mutator,
      iteration: e.iteration,
      crashed: !!e.crashed,
      newEdges: e.newEdgeCount || 0,
    });
    if (stalkLiveTimeline.length > 200) stalkLiveTimeline = stalkLiveTimeline.slice(-200);
    if (document.getElementById('view-dashboard').classList.contains('visible')) {
      document.getElementById('stalk-status').textContent = e.crashed ? 'Crash Detected' : 'Tracing';
      document.getElementById('stalk-status').className = statusClass(e.crashed ? 'Crash Detected' : 'Tracing');
      renderTimeline(stalkLiveTimeline);
    }
  });

  hub.on('fuzzCompleted', (e) => {
    appendLog(`■ Done — ${e.iterations} iters, ${e.crashesFound} crashes, +${e.corpusAdded} corpus`);
    setStatus('Completed');
    startBtn.disabled = false;
    loadDashboard();
    loadCrashes();
  });

  hub.on('fuzzStopped', (e) => {
    appendLog(`■ Stopped: ${e.reason}`);
    setStatus('Stopped');
    startBtn.disabled = false;
    loadDashboard().catch(() => {});
  });

  hub.on('fuzzError', (e) => {
    appendLog(`✖ Error: ${e.message}`, 'crash');
    setStatus('Error');
    startBtn.disabled = false;
  });

  await hub.start();
}

document.getElementById('fuzz-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  logEl.innerHTML = '';
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
    });
    appendLog('Session accepted…');
  } catch (err) {
    appendLog(err.message, 'crash');
  }
});

stopBtn.addEventListener('click', async () => {
  try {
    await api.post('/api/fuzz/stop', {});
  } catch (err) {
    appendLog(err.message, 'crash');
  }
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
    const report = await api.get(`/api/doctor?configPath=${encodeURIComponent(configPath)}`);
    box.innerHTML = report.checks.map((c) => {
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

async function renderGraph(configPath) {
  const status = document.getElementById('graph-status');
  const meta = document.getElementById('graph-meta');
  const diagram = document.getElementById('graph-diagram');
  const edgesEl = document.getElementById('graph-edges');
  const yamlEl = document.getElementById('graph-yaml');

  status.textContent = 'Loading…';
  const report = await api.get(`/api/graph?configPath=${encodeURIComponent(configPath)}`);

  if (!report.hasGraph) {
    status.textContent = `${report.project}: no sessionGraph — use sessionFlows for linear chains.`;
    status.className = 'status-box warn';
    meta.innerHTML = `<p>Session commands: ${(report.commands || []).map((c) => `<code>${c}</code>`).join(' ') || '—'}</p>`;
    diagram.innerHTML = '';
    edgesEl.innerHTML = '';
    yamlEl.value = '';
    return;
  }

  status.className = `status-box ${report.valid ? 'ok' : 'crash'}`;
  status.textContent = report.valid
    ? `Valid graph — start=${report.start}, mutate=${report.mutate}`
    : `Invalid graph — fix errors below`;

  const warnHtml = (report.warnings || []).map((w) => `<div class="warn">⚠ ${w}</div>`).join('');
  const errHtml = (report.errors || []).map((e) => `<div class="crash">✗ ${e}</div>`).join('');
  meta.innerHTML = `
    <p><strong>${report.project}</strong> · start <code>${report.start}</code> · mutate <code>${report.mutate || '—'}</code></p>
    ${errHtml}${warnHtml}
    <p class="hex">Commands: ${(report.commands || []).map((c) => `<code>${c}</code>`).join(' ')}</p>`;

  yamlEl.value = report.yamlSnippet || '';

  if (report.mermaid) {
    diagram.innerHTML = `<pre class="mermaid">${report.mermaid}</pre>`;
    if (window.mermaid) {
      mermaid.initialize({ startOnLoad: false, theme: 'dark', securityLevel: 'loose' });
      await mermaid.run({ nodes: diagram.querySelectorAll('.mermaid') });
    }
  } else {
    diagram.innerHTML = '<p class="empty">No edges defined.</p>';
  }

  const edges = report.edges || [];
  if (!edges.length) {
    edgesEl.innerHTML = '';
  } else {
    edgesEl.innerHTML = `<table><thead><tr><th>From</th><th>When (response contains)</th><th>To</th></tr></thead>
      <tbody>${edges.map((e) => `<tr class="${e.to === report.mutate ? 'mutate-row' : ''}">
        <td><code>${e.from}</code></td>
        <td><code>${e.when || '?'}</code></td>
        <td><code>${e.to}</code>${e.to === report.mutate ? ' ★ mutate' : ''}</td>
      </tr>`).join('')}</tbody></table>`;
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
  sel.innerHTML = targets.map((t) => `<option value="${t.configPath}">${t.name}</option>`).join('');
}

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

async function pollStatus() {
  try {
    const s = await api.get('/api/fuzz/status');
    if (s.running) {
      startBtn.disabled = true;
      setStatus(`${s.phase}: ${s.lastMessage || '…'}`);
      stalkPollTick += 1;
      if (stalkPollTick % 3 === 0 && document.getElementById('view-dashboard').classList.contains('visible'))
        loadDashboard().catch(() => {});
    } else if (s.phase === 'idle') {
      startBtn.disabled = false;
      stalkPollTick = 0;
    }
  } catch { /* ignore */ }
}

/* —— Case builder (CyberChef / Sulley-style recipe → seed + dict) —— */
let caseOps = [];
let caseSteps = [];

document.querySelectorAll('.fuzz-subtab').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.fuzz-subtab').forEach((b) => b.classList.toggle('active', b === btn));
    const tab = btn.dataset.fuzzTab;
    document.getElementById('fuzz-tab-campaign')?.classList.toggle('hidden', tab !== 'campaign');
    document.getElementById('fuzz-tab-cases')?.classList.toggle('hidden', tab !== 'cases');
    if (tab === 'cases') loadCaseBuilder().catch(() => {});
  });
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
  renderCaseSteps();
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

function renderCaseSteps() {
  const el = document.getElementById('case-steps');
  if (!caseSteps.length) {
    el.innerHTML = '<p class="hint">No blocks yet — click an op on the left, or use a preset.</p>';
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
    });
  });
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
        ? 'File-format target (no host/port).'
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

document.getElementById('case-preview')?.addEventListener('click', async () => {
  try {
    const preview = await api.post('/api/case/preview', { steps: collectCaseSteps() });
    document.getElementById('case-preview-meta').textContent =
      `${preview.length} bytes` + ((preview.notes || []).length ? ` — ${preview.notes.join(' ')}` : '');
    document.getElementById('case-preview-ascii').textContent = preview.asciiPreview || '';
    document.getElementById('case-preview-hex').textContent = preview.hexPreview || '';
    document.getElementById('case-preview-hints').innerHTML =
      (preview.dictionaryHints || []).map((h) => `<li>${escapeAttr(h)}</li>`).join('') ||
      '<li class="hint">(none — mark text/delim as fuzzable)</li>';
  } catch (err) {
    document.getElementById('case-preview-meta').textContent = err.message;
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
  if (fmt === 'file-xml' && (ext.value === '.bin' || !ext.value)) ext.value = '.xml';
  if (fmt === 'file-framed' || fmt === 'file-magic' || fmt === 'file-blank') {
    if (!ext.value || ext.value === '.xml') ext.value = '.bin';
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
    await loadTargets();
    const caseSel = document.getElementById('case-project');
    const sanitized = name.trim().toLowerCase().replace(/[^a-z0-9_\-]+/g, '-').replace(/^-|-$/g, '');
    if (caseSel && [...caseSel.options].some((o) => o.value === sanitized))
      caseSel.value = sanitized;
    await refreshCaseProject();
    // Apply matching seed preset for file starters
    if (isFile) {
      const fmt = document.getElementById('case-new-file-format')?.value;
      if (fmt === 'file-xml') document.getElementById('case-preset-xml')?.click();
      else if (fmt === 'file-framed') document.getElementById('case-preset-file-framed')?.click();
      else if (fmt === 'file-magic') document.getElementById('case-preset-file-magic')?.click();
      else document.getElementById('case-preset-file-blank')?.click();
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

async function importCaseBytes(asHex) {
  const raw = document.getElementById('case-import-text').value;
  if (!raw.trim()) return;
  try {
    const body = asHex ? { hex: raw } : { text: raw };
    const r = await api.post('/api/case/import', body);
    caseSteps = (r.suggestedSteps || []).map((s) => ({
      op: s.op,
      value: s.value || '',
      count: s.count ?? 16,
      format: s.format || 'u32le',
      role: s.role || 'fuzzable',
    }));
    renderCaseSteps();
    document.getElementById('case-save-result').textContent =
      `Imported ${r.length} bytes → ${caseSteps.length} block(s)`;
  } catch (err) {
    document.getElementById('case-save-result').textContent = err.message;
  }
}

document.getElementById('case-import-hex')?.addEventListener('click', () => importCaseBytes(true));
document.getElementById('case-import-text-btn')?.addEventListener('click', () => importCaseBytes(false));

document.getElementById('case-clear')?.addEventListener('click', () => {
  caseSteps = [];
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

document.getElementById('case-preset-ftp')?.addEventListener('click', () => {
  caseSteps = [
    { op: 'static', value: 'USER', role: 'static' },
    { op: 'delim', value: ' ', role: 'fuzzable' },
    { op: 'text', value: 'anonymous', role: 'fuzzable' },
    { op: 'crlf', role: 'static' },
  ];
  renderCaseSteps();
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

async function init() {
  initNavToggle();
  await loadHealth();
  await loadTargets();
  await loadDashboard();
  await loadStalkingView().catch(() => {});
  await loadRoadmap();
  await loadLegs();
  await loadModels();
  await loadBundlesView();
  await loadCrashes();
  await connectHub();
  setInterval(pollStatus, 3000);
  setInterval(() => {
    if (document.getElementById('view-proxy').classList.contains('visible'))
      loadProxy().catch(() => {});
  }, 4000);
}

init().catch((err) => {
  document.body.insertAdjacentHTML('beforeend', `<p class="empty">Failed to load UI: ${err.message}</p>`);
});
