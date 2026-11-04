const $ = (s, el=document) => el.querySelector(s);
const $$ = (s, el=document) => [...el.querySelectorAll(s)];
const api = (u, opt) => fetch(u, opt).then(r => r.ok ? r.json() : r.json().then(e=>Promise.reject(e)));
const esc = s => (s ?? "").toString().replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

let current = null;        // selected target id
let activeTab = "overview";
let pollTimer = null;

let _plan = null;
async function loadPlan(){
  _plan = await api("/api/plan");
}
function toggleEnv(){
  const p = $("#env-panel");
  if(p.style.display === "none"){ renderEnv(); p.style.display = "block"; }
  else { p.style.display = "none"; }
}
function renderEnv(){
  if(!_plan){ $("#env-panel").innerHTML = "loading…"; return; }
  const rows = _plan.map(r => {
    const cls = r.using_tool ? "ok" : (r.engine.includes("DISABLED") ? "down" : "warn");
    const tag = r.using_tool ? "tool" : (r.engine.includes("DISABLED") ? "OFF" : "built-in");
    const note = r.note ? `<div class="env-note">! ${esc(r.note)}</div>` : "";
    return `<tr><td class="mono">${esc(r.stage)}</td>
      <td><span class="badge ${cls==='ok'?'new':(cls==='warn'?'medium':'critical')}">${tag}</span></td>
      <td>${esc(r.engine)}${note}</td></tr>`;
  }).join("");
  const missing = [...new Set(_plan.flatMap(r => r.missing))];
  let install = "";
  if(missing.length){
    const lines = missing.map(m => {
      const cmd = (_plan.find(r => r.install && r.install[m]) || {install:{}}).install[m] || "";
      return `<tr><td class="mono">${esc(m)}</td><td class="mono">${esc(cmd)}</td></tr>`;
    }).join("");
    install = `<h4>Not installed — install the real tools (optional, faster/more complete):</h4>
      <table>${lines}</table>
      <div class="hint">Nuclei has NO built-in fallback — install it for vuln scanning. Others fall back automatically.</div>`;
  } else {
    install = `<div class="hint">All optional tools are installed. 🎉</div>`;
  }
  $("#env-panel").innerHTML = `
    <h4>What runs each stage right now</h4>
    <table><thead><tr><th>stage</th><th>mode</th><th>engine</th></tr></thead><tbody>${rows}</tbody></table>
    ${install}`;
}

async function loadTargets(){
  const ts = await api("/api/targets");
  const el = $("#targets");
  if(!ts.length){ el.innerHTML = `<div class="hint">No targets yet.</div>`; return; }
  el.innerHTML = ts.map(t => `
    <div class="target ${t.id===current?'active':''}" data-id="${t.id}">
      <div class="dom">${esc(t.domain)}
        <span class="dot ${t.health||'unknown'}" title="health: ${t.health}"></span></div>
      <div class="meta">
        <span>sub ${t.counts.subdomains}</span>
        <span>http ${t.counts.http_services}</span>
        <span>js ${t.counts.js_findings}</span>
        <span>vuln ${t.counts.findings}</span>
        ${t.running?`<span class="pill running">${esc(t.scan_stage||'running')}</span>`:
          (t.scan_status?`<span class="pill ${t.scan_status}">${esc(t.scan_status)}</span>`:'')}
      </div>
    </div>`).join("");
  $$(".target", el).forEach(d => d.onclick = () => selectTarget(+d.dataset.id));
}

async function selectTarget(id){
  current = id; activeTab = activeTab || "overview";
  await loadTargets();
  await renderDetail();
}

function sev(s){ return `<span class="badge ${s||'info'}">${esc(s||'info')}</span>`; }

async function renderDetail(){
  if(current === null) return;
  const d = await api(`/api/targets/${current}`);
  const c = d.counts, t = d.target, run = d.run || {};
  const statusPill = d.running ? `<span class="pill running">${esc(run.stage||'running')}</span>`
      : (run.status ? `<span class="pill ${run.status}">${esc(run.status)}</span>` : '');
  const tabs = ["overview","subdomains","services","ports","js","vulns","health","log"];
  const detail = $("#detail");
  detail.innerHTML = `
    <h2>${esc(t.domain)} <span class="dot ${t.health||'unknown'}"></span> ${statusPill}</h2>
    <div class="acts">
      <button onclick="startScan(${current}, true)" ${d.running?'disabled':''}>▶ Run full scan</button>
      <button class="ghost" onclick="startScan(${current}, false)" ${d.running?'disabled':''}>▶ Scan (no nuclei)</button>
      <button class="ghost" onclick="editAuth(${current})">${(t.auth_cookie||t.auth_headers)?'🔑 Auth set':'🔑 Set auth'}</button>
      <button class="ghost" onclick="window.open('/api/targets/${current}/report','_blank')">📄 Report</button>
      <button class="ghost" onclick="renderDetail()">⟳ Refresh</button>
    </div>
    <div class="stat-row">
      <div class="stat"><div class="n">${c.subdomains}</div><div class="l">Subdomains</div></div>
      <div class="stat"><div class="n">${c.http_services}</div><div class="l">Live HTTP</div></div>
      <div class="stat"><div class="n">${c.js_findings}</div><div class="l">JS findings</div></div>
      <div class="stat"><div class="n">${c.findings}</div><div class="l">Vulns</div></div>
    </div>
    <div class="tabs">${tabs.map(x=>`<div class="tab ${x===activeTab?'active':''}" data-tab="${x}">${x}</div>`).join("")}</div>
    <div id="tab-body"></div>`;
  $$(".tab", detail).forEach(el => el.onclick = () => { activeTab = el.dataset.tab; renderDetail(); });
  renderTab(d);
}

function renderTab(d){
  const body = $("#tab-body");
  if(activeTab==="overview"){
    const run = d.run||{};
    let stats = {}; try{ stats = JSON.parse(run.stats||"{}"); }catch(e){}
    body.innerHTML = `
      <div class="hint">Last run: ${run.status||'never'} ${run.stage?('· stage '+esc(run.stage)):''}</div>
      <table><tbody>
        ${Object.entries(stats).map(([k,v])=>`<tr><td>${esc(k)}</td><td class="mono">${esc(v)}</td></tr>`).join("")||'<tr><td class="hint">No stats yet — run a scan.</td></tr>'}
      </tbody></table>`;
  }
  else if(activeTab==="subdomains"){
    body.innerHTML = tableOr(d.subdomains, ["subdomain"],
      r => `<tr><td class="mono">${esc(r.value)} ${r.is_new?'<span class="badge new">new</span>':''}</td></tr>`);
  }
  else if(activeTab==="services"){
    body.innerHTML = tableOr(d.services, ["url","status","title","tech","waf / cdn","ip","shot"],
      r => {
        const wc = [r.waf?`<span class="badge high">${esc(r.waf)}</span>`:'', r.cdn?`<span class="badge low">${esc(r.cdn)}</span>`:''].filter(Boolean).join(' ')||'—';
        const shot = r.screenshot ? `<a href="/api/screenshot?path=${encodeURIComponent(r.screenshot)}" target="_blank">📷</a>` : '';
        return `<tr><td class="mono">${esc(r.url)}</td><td>${esc(r.status)}</td><td>${esc(r.title)}</td>
            <td>${esc(r.tech)}</td><td>${wc}</td><td class="mono">${esc(r.ip)}</td><td>${shot}</td></tr>`;
      });
  }
  else if(activeTab==="ports"){
    const rows = (d.ports||[]).map(p => { let m={}; try{m=JSON.parse(p.meta||"{}");}catch(e){} return {host:p.host, ports:(m.ports||[]).join(", ")}; });
    body.innerHTML = tableOr(rows, ["host","open ports"],
      r => `<tr><td class="mono">${esc(r.host)}</td><td class="mono">${esc(r.ports)}</td></tr>`);
  }
  else if(activeTab==="js"){
    body.innerHTML = tableOr(d.js_findings, ["sev","kind","name","value","source"],
      r => `<tr><td>${sev(r.severity)}</td><td>${esc(r.kind)}</td><td>${esc(r.name)}</td>
            <td class="mono">${esc(r.value)}</td><td class="mono">${esc(r.source_url)}</td></tr>`);
  }
  else if(activeTab==="vulns"){
    body.innerHTML = tableOr(d.findings, ["sev","engine","name","template","matched"],
      r => `<tr><td>${sev(r.severity)}</td><td>${esc(r.engine)}</td><td>${esc(r.name)}</td>
            <td class="mono">${esc(r.template)}</td><td class="mono">${esc(r.matched_at)}</td></tr>`);
  }
  else if(activeTab==="health"){ renderHealth(); }
  else if(activeTab==="log"){ renderLog(); }
}

function tableOr(rows, cols, rowFn){
  if(!rows || !rows.length) return `<div class="hint">Nothing here yet.</div>`;
  return `<table><thead><tr>${cols.map(c=>`<th>${c}</th>`).join("")}</tr></thead>
    <tbody>${rows.map(rowFn).join("")}</tbody></table>`;
}

async function renderHealth(){
  const h = await api(`/api/targets/${current}/health`);
  const body = $("#tab-body");
  if(!h.checks.length){ body.innerHTML = `<div class="hint">No health samples yet — monitor runs during a scan.</div>`; return; }
  const byHost = {};
  h.checks.forEach(c => (byHost[c.host] ??= []).push(c));
  body.innerHTML = `<div class="hint">Live availability sampled during scans. The scan auto-pauses when a target goes <b>degraded</b>/<b>down</b>.</div>` +
    Object.entries(byHost).map(([host, cs]) => {
      const bars = cs.slice(-120).map(c => {
        const cls = !c.up ? 'down' : (c.response_ms>3000?'slow':'');
        const hpx = Math.max(6, Math.min(60, (c.response_ms||0)/60));
        return `<div class="hb ${cls}" style="height:${hpx}px" title="${c.response_ms}ms status ${c.status}"></div>`;
      }).join("");
      const last = cs[cs.length-1];
      return `<div class="card"><div class="dom">${esc(host)} <span class="mono">${last.response_ms}ms · ${last.up?'up':'down'}</span></div>
        <div class="health-bars">${bars}</div></div>`;
    }).join("");
}

async function renderLog(){
  const l = await api(`/api/targets/${current}/log`);
  $("#tab-body").innerHTML = `<div class="log">${esc(l.log)||'(no log yet)'}</div>`;
}

async function editAuth(id){
  const cookie = prompt("Session cookie for in-scope hosts (blank to clear):\ne.g. sid=abc123; csrf=xyz", "");
  if(cookie === null) return;
  const headers = prompt("Extra headers, one per line (blank for none):\ne.g. Authorization: Bearer eyJ…", "");
  if(headers === null) return;
  const r = await api(`/api/targets/${id}/auth`, {method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({auth_cookie:cookie, auth_headers:headers, clear_auth:true})});
  alert("Auth updated — cookie:" + r.has_cookie + " headers:" + r.has_headers + "\nSent only to in-scope hosts.");
  renderDetail();
}

async function startScan(id, nuclei){
  try{
    await api(`/api/targets/${id}/scan`, {method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({nuclei})});
    activeTab = "log";
    renderDetail();
  }catch(e){ alert("Could not start scan: " + (e.detail||JSON.stringify(e))); }
}

$("#add-form").onsubmit = async (e) => {
  e.preventDefault();
  const domain = $("#domain").value.trim();
  if(!domain) return;
  const r = await api("/api/targets", {method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({domain, scope_in:$("#scope_in").value, scope_out:$("#scope_out").value,
      auth_cookie:$("#auth_cookie").value, auth_headers:$("#auth_headers").value})});
  $("#domain").value=""; $("#scope_in").value=""; $("#scope_out").value="";
  $("#auth_cookie").value=""; $("#auth_headers").value="";
  await loadTargets();
  selectTarget(r.id);
};

function startPolling(){
  if(pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    await loadTargets();
    if(current!==null && (activeTab==="log"||activeTab==="health"||activeTab==="overview")){
      const d = await api(`/api/targets/${current}`);
      if(d.running || (d.run && d.run.status==='running')){
        if(activeTab==="log") renderLog();
        else if(activeTab==="health") renderHealth();
        else renderDetail();
      }
    }
  }, 4000);
}

loadPlan();
loadTargets();
startPolling();
