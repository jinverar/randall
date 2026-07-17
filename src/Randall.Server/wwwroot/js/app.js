const api = {
  get: (path) => fetch(path).then((r) => {
    if (!r.ok) throw new Error(`${r.status} ${path}`);
    return r.json();
  }),
  post: (path, body) => fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }).then(async (r) => {
    const data = r.status === 204 ? null : await r.json().catch(() => null);
    if (!r.ok) throw new Error(data?.error || `${r.status} ${path}`);
    return data;
  }),
};

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
  if (name === 'proxy') loadProxy().catch(() => {});
  if (name === 'campaign') loadCampaignView().catch(() => {});
  if (name === 'models') loadModels().catch(() => {});
  if (name === 'graph') loadGraphView().catch(() => {});
  if (name === 'bundles') loadBundlesView().catch(() => {});
}

document.querySelectorAll('.nav-btn').forEach((btn) => {
  btn.addEventListener('click', () => switchView(btn.dataset.view));
});

async function loadHealth() {
  const h = await api.get('/api/health');
  document.getElementById('health-label').textContent = `${h.name} ${h.version} · ${h.status}`;
}

async function loadTargets() {
  const targets = await api.get('/api/targets');
  const sel = document.getElementById('fuzz-target');
  const filter = document.getElementById('crash-filter');
  sel.innerHTML = targets.map((t) => `<option value="${t.configPath}">${t.name} [${t.kind}]</option>`).join('');
  filter.innerHTML = '<option value="">All</option>' +
    targets.map((t) => `<option value="${t.name}">${t.name}</option>`).join('');

  const dash = document.getElementById('dashboard-targets');
  if (!targets.length) {
    dash.innerHTML = '<p class="empty">No projects in projects/</p>';
    return;
  }
  dash.innerHTML = `<table><thead><tr><th>Name</th><th>Kind</th><th>Description</th></tr></thead><tbody>
    ${targets.map((t) => `<tr>
      <td><strong>${t.name}</strong></td>
      <td><span class="badge ${t.kind}">${t.kind}</span></td>
      <td>${t.description}</td>
    </tr>`).join('')}
  </tbody></table>`;
  return targets;
}

async function loadDashboard() {
  const [targets, coverage, crashes] = await Promise.all([
    api.get('/api/targets'),
    api.get('/api/coverage/status'),
    api.get('/api/crashes'),
  ]);

  let totalEdges = 0;
  for (const t of targets) {
    try {
      const stats = await api.get(`/api/corpus/${t.name}`);
      totalEdges += stats.coverageEdges;
    } catch { /* ignore */ }
  }

  document.getElementById('dashboard-cards').innerHTML = `
    <div class="card"><div class="label">Targets</div><div class="value">${targets.length}</div></div>
    <div class="card"><div class="label">Crashes</div><div class="value">${crashes.length}</div></div>
    <div class="card ${coverage.dynamoRioAvailable ? 'ok' : 'warn'}">
      <div class="label">DynamoRIO</div>
      <div class="value">${coverage.dynamoRioAvailable ? 'Ready' : 'Missing'}</div>
      ${coverage.drrunPath ? `<div class="hex" style="margin-top:0.35rem;font-size:0.72rem">${coverage.drrunPath.split(/[/\\]/).slice(-3).join('/')}</div>` : ''}
    </div>
    <div class="card"><div class="label">Coverage edges</div><div class="value">${totalEdges}</div></div>`;
}

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

function renderCrashDetail(detail, title) {
  const box = document.getElementById('crash-detail');
  box.classList.remove('hidden');
  const s = detail.sidecar;
  const why = s?.exceptionHint
    ? `${s.exceptionHint}${s.targetDetail ? ` · ${s.targetDetail}` : ''}`
    : (detail.summary.targetExitCode ? `exit ${detail.summary.targetExitCode}` : '');
  box.innerHTML = `
    <h3>${title}</h3>
    <p>Mutator: <code>${detail.summary.mutator}</code> · Hash: <code>${detail.summary.inputHash}</code></p>
    ${s?.command ? `<p>Command: <code>${s.command}</code></p>` : ''}
    ${why ? `<p><strong>Why:</strong> <code>${why}</code></p>` : ''}
    ${detail.summary.triageTag ? `<p>Tag: <code>${detail.summary.triageTag}</code></p>` : ''}
    ${s?.parentInputHash ? `<p>Parent hash: <code>${s.parentInputHash}</code> · source: <code>${s.seedSource}</code></p>` : ''}
    ${s?.newEdgesAtCrash != null ? `<p>Coverage at crash: +${s.newEdgesAtCrash} new (total ${s.totalEdgesAtCrash}) · backend <code>${s.stalkBackend}</code></p>` : ''}
    ${s?.runId ? `<p>Run: <code>${s.runId}</code></p>` : ''}
    ${detail.analysis?.ok ? `<p>Fault: <code>${detail.analysis.faultAddress || '?'}</code>${detail.analysis.faultModule ? ` in <code>${detail.analysis.faultModule}</code>` : ''}</p>` : ''}
    ${detail.analysis?.registers?.rip ? `<p>RIP=<code>${detail.analysis.registers.rip}</code> RSP=<code>${detail.analysis.registers.rsp}</code></p>` : ''}
    <p>Length: ${detail.inputLength} bytes · Id: <code>${detail.summary.id}</code></p>
    <p class="label">Payload (ASCII, first 256 bytes)</p>
    <pre class="ascii-preview">${detail.asciiPreview || '(none)'}</pre>
    <p class="label">Payload (hex)</p>
    <p class="hex-preview">${detail.hexPreview}</p>
    <p><code>${detail.summary.inputPath}</code></p>
    <button type="button" class="btn primary" id="export-crash-btn">Export triage bundle</button>
    <p id="export-result" class="empty"></p>`;
  document.getElementById('export-crash-btn')?.addEventListener('click', async () => {
    try {
      const bundle = await api.post(`/api/crashes/${detail.summary.id}/export`, {});
      document.getElementById('export-result').textContent = `Exported to ${bundle.exportPath}`;
    } catch (err) {
      document.getElementById('export-result').textContent = err.message;
    }
  });
  box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function loadCrashes(project = '') {
  const url = project ? `/api/crashes?project=${encodeURIComponent(project)}` : '/api/crashes';
  const clusterUrl = project ? `/api/crashes/clusters?project=${encodeURIComponent(project)}` : '/api/crashes/clusters';
  const [crashes, clusters] = await Promise.all([
    api.get(url),
    api.get(clusterUrl).catch(() => []),
  ]);
  const el = document.getElementById('crashes-table');
  const clusterEl = document.getElementById('crash-clusters');
  if (clusterEl) {
    if (!clusters.length) {
      clusterEl.innerHTML = '<p class="empty">No crash clusters yet.</p>';
    } else {
      clusterEl.innerHTML = `<table><thead><tr><th>Cluster</th><th>Project</th><th>Count</th><th>Rep. mutator</th></tr></thead>
        <tbody>${clusters.map((c) => `<tr class="clickable" data-id="${c.representativeId}">
          <td><code>${c.clusterId.split(':').slice(1).join(':') || c.clusterId}</code></td>
          <td>${c.project}</td><td><strong>${c.count}</strong></td>
          <td><code>${c.representativeMutator}</code></td></tr>`).join('')}
        </tbody></table>`;
      clusterEl.querySelectorAll('tr.clickable').forEach((row) => {
        row.addEventListener('click', async () => {
          const detail = await api.get(`/api/crashes/${row.dataset.id}`);
          renderCrashDetail(detail, `Cluster representative — ${detail.summary.project}`);
        });
      });
    }
  }
  if (!crashes.length) {
    el.innerHTML = '<p class="empty">No crashes yet — start a fuzz run from the Fuzz tab.</p>';
    return;
  }
  el.innerHTML = `<table><thead><tr><th>When</th><th>Project</th><th>Iter</th><th>Mutator</th><th>Tag</th><th>Input</th></tr></thead>
    <tbody>${crashes.map((c) => `<tr class="clickable" data-id="${c.id}">
      <td>${new Date(c.observedAt).toLocaleString()}</td>
      <td>${c.project}</td><td>${c.iteration}</td><td>${c.mutator}</td>
      <td>${c.triageTag ? `<code>${c.triageTag}</code>` : '—'}</td>
      <td><code>${c.inputPath.split(/[/\\]/).pop()}</code></td>
    </tr>`).join('')}</tbody></table>`;

  el.querySelectorAll('tr.clickable').forEach((row) => {
    row.addEventListener('click', async () => {
      const detail = await api.get(`/api/crashes/${row.dataset.id}`);
      renderCrashDetail(detail, `Crash ${detail.summary.project} #${detail.summary.iteration}`);
    });
  });
}

document.getElementById('crash-filter').addEventListener('change', (e) => {
  loadCrashes(e.target.value);
});

let hub;

async function connectHub() {
  hub = new signalR.HubConnectionBuilder().withUrl('/hubs/fuzz').withAutomaticReconnect().build();

  hub.on('fuzzStarted', (e) => {
    appendLog(`▶ Started ${e.project} (${e.kind})`);
    setStatus(`Running ${e.project}…`);
    startBtn.disabled = true;
  });

  hub.on('fuzzIteration', (e) => {
    const cls = e.crashed ? 'crash' : e.newCoverage ? 'cov' : '';
    const tag = e.crashed ? 'CRASH' : e.newCoverage ? `+${e.newEdgeCount} edges` : 'ok';
    appendLog(`#${e.iteration} ${e.mutator} len=${e.payloadLength} ${tag}`, cls);
    setStatus(`iter ${e.iteration} · corpus ${e.corpusSize} · edges ${e.coverageEdgeTotal}`);
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
  const targets = await api.get('/api/targets');
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
  const targets = await api.get('/api/targets');
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
    } else if (s.phase === 'idle') {
      startBtn.disabled = false;
    }
  } catch { /* ignore */ }
}

async function init() {
  await loadHealth();
  await loadTargets();
  await loadDashboard();
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
