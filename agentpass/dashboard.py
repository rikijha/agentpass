"""The single-page admin dashboard served at "/"."""

DASHBOARD_HTML = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>AgentPass</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 :root{--b:#d0d7de;--muted:#57606a;--bg:#f6f8fa;--green:#1a7f37;--red:#cf222e;--amber:#9a6700;--blue:#0969da}
 *{box-sizing:border-box}
 body{font:14px/1.5 -apple-system,system-ui,sans-serif;max-width:1100px;margin:32px auto;padding:0 16px;color:#1f2328}
 h1{margin:0} .sub{color:var(--muted);margin:4px 0 20px}
 h3{margin:28px 0 8px;display:flex;align-items:center;gap:12px}
 input[type=text],input[type=number],input:not([type]){padding:6px 8px;border:1px solid var(--b);border-radius:6px;font:inherit}
 input[type=number]{width:96px}
 button{padding:6px 12px;border:1px solid var(--b);border-radius:6px;background:var(--bg);cursor:pointer;font:inherit}
 button.primary{background:#1f883d;border-color:#1a7f37;color:#fff;font-weight:600}
 button.small{padding:2px 8px;font-size:12px}
 table{border-collapse:collapse;width:100%} td,th{border-bottom:1px solid #eaeef2;padding:6px 8px;text-align:left;vertical-align:top}
 th{color:var(--muted);font-weight:600} code,pre{font:12px ui-monospace,SFMono-Regular,Menlo,monospace}
 .allow,.allow_approved,.ok,.approved,.active{color:var(--green);font-weight:600}
 .deny,.denied,.revoked,.error{color:var(--red);font-weight:600}
 .needs_approval,.pending{color:var(--amber);font-weight:600}
 .card{border:1px solid var(--b);border-radius:8px;padding:16px;margin:8px 0 16px;background:#fff}
 .row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px} .row label{display:flex;flex-direction:column;gap:4px;color:var(--muted);font-size:12px}
 .row label input{color:#1f2328;font-size:14px;width:220px}
 .hint{color:var(--muted);font-size:12px} .err{color:var(--red);margin-top:8px;white-space:pre-wrap}
 .tools td{vertical-align:middle} .tools input[type=number]:disabled{background:var(--bg)}
 .result{border-color:#1a7f37;background:#f0fff4} .warn{color:var(--amber);font-weight:600}
 pre{background:var(--bg);border:1px solid #eaeef2;border-radius:6px;padding:10px;overflow:auto;margin:6px 0}
 .chip{display:inline-block;background:var(--bg);border:1px solid #eaeef2;border-radius:10px;padding:0 8px;margin:1px 2px;font-size:12px}
 .empty{color:var(--muted)} .hidden{display:none}
</style></head><body>
<h1>AgentPass</h1><p class="sub">Identity, permissions and audit for AI agents</p>
<p>Admin key: <input id="key" value="dev-admin-key"> <button onclick="load()">Refresh</button></p>

<h3>Agents <button class="primary" id="toggleAdd" onclick="toggleAdd()">+ Add agent</button></h3>

<div id="addCard" class="card hidden">
  <div class="row">
    <label>Name<input id="f_name" placeholder="shopping-agent"></label>
    <label>Owner<input id="f_owner" value="riki"></label>
    <label>Purpose<input id="f_purpose" placeholder="weekly groceries" style="width:320px"></label>
  </div>
  <div class="hint">Tools this agent may use. Leave limits blank for none. Amounts in ₹.</div>
  <table class="tools" id="f_tools"></table>
  <div class="row" style="margin-top:14px;align-items:center">
    <label style="flex-direction:row;align-items:center;color:#1f2328;font-size:14px">
      <input type="checkbox" id="f_delegate" checked style="margin-right:6px">
      Give it access now for user&nbsp;<input id="f_user" value="riki" style="width:110px">&nbsp;for&nbsp;
      <input type="number" id="f_ttl" value="24" min="1" style="width:70px">&nbsp;hours
    </label>
  </div>
  <button class="primary" onclick="createAgent()">Create agent</button>
  <button onclick="toggleAdd()">Cancel</button>
  <div class="err" id="f_err"></div>
</div>

<div id="resultCard" class="card result hidden"></div>

<table id="agents"></table>
<h3>Pending approvals</h3><table id="approvals"></table>
<h3>Audit log</h3><table id="audit"></table>

<script>
const $ = id => document.getElementById(id);
const h = (json) => Object.assign({'X-Admin-Key': $('key').value}, json ? {'Content-Type':'application/json'} : {});
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(method, path, body){
  const r = await fetch(path, {method, headers: h(!!body), body: body ? JSON.stringify(body) : undefined});
  let data = {}; try { data = await r.json(); } catch(e) {}
  if (!r.ok) throw new Error(data.message || ('HTTP ' + r.status));
  return data;
}
async function post(p){ try { await api('POST', p); } catch(e) { alert(e.message); } load(); }

let TOOLS = [];
async function loadTools(){
  try { TOOLS = (await api('GET','/tools')).tools; } catch(e) { TOOLS = []; }
  $('f_tools').innerHTML = '<tr><th></th><th>Tool</th><th>Max per call</th><th>Approval above</th><th>Budget</th><th>per days</th><th>Always ask me</th></tr>' +
    TOOLS.map((t,i) => `<tr>
      <td><input type="checkbox" id="t_on_${i}" onchange="syncRow(${i})"></td>
      <td><code>${esc(t)}</code></td>
      <td><input type="number" min="1" id="t_max_${i}" disabled></td>
      <td><input type="number" min="1" id="t_appr_${i}" disabled></td>
      <td><input type="number" min="1" id="t_bud_${i}" disabled></td>
      <td><input type="number" min="1" id="t_days_${i}" value="7" disabled style="width:60px"></td>
      <td><input type="checkbox" id="t_always_${i}" disabled></td></tr>`).join('');
}
function syncRow(i){
  const on = $('t_on_'+i).checked;
  ['max','appr','bud','days','always'].forEach(k => $('t_'+k+'_'+i).disabled = !on);
}
function toggleAdd(){
  const c = $('addCard'); c.classList.toggle('hidden');
  $('toggleAdd').classList.toggle('hidden', !c.classList.contains('hidden'));
  $('f_err').textContent = '';
  if (!c.classList.contains('hidden')) $('f_name').focus();
}
async function createAgent(){
  $('f_err').textContent = '';
  const tools = {};
  TOOLS.forEach((t,i) => {
    if (!$('t_on_'+i).checked) return;
    const r = {}, v = k => $('t_'+k+'_'+i).value.trim();
    if (v('max')) r.max_amount = Number(v('max'));
    if (v('appr')) r.require_approval_above = Number(v('appr'));
    if (v('bud')) r.budget = {amount: Number(v('bud')), period_days: Number(v('days') || 7)};
    if ($('t_always_'+i).checked) r.require_approval = true;
    tools[t] = r;
  });
  if (!Object.keys(tools).length) { $('f_err').textContent = 'Pick at least one tool.'; return; }
  let agent, dlg = null;
  try {
    agent = await api('POST', '/agents', {name: $('f_name').value.trim(), owner: $('f_owner').value.trim(),
                                           purpose: $('f_purpose').value.trim(), tools});
  } catch(e) { $('f_err').textContent = e.message; return; }
  if ($('f_delegate').checked) {
    try {
      dlg = await api('POST', '/delegations', {agent_id: agent.agent_id, user_id: $('f_user').value.trim(),
                                               scopes: Object.keys(tools), ttl_minutes: Number($('f_ttl').value || 24) * 60});
    } catch(e) { dlg = {error: e.message}; }
  }
  showResult(agent, dlg);
  ['f_name','f_purpose'].forEach(id => $(id).value = '');
  TOOLS.forEach((t,i) => { $('t_on_'+i).checked = false; syncRow(i); ['max','appr','bud'].forEach(k => $('t_'+k+'_'+i).value=''); $('t_always_'+i).checked=false; });
  toggleAdd(); load();
}
let LAST_KEY = '', LAST_NAME = '';
function showResult(agent, dlg){
  LAST_KEY = agent.private_key_pem || ''; LAST_NAME = agent.name;
  const snippet = `from agentpass.client import AgentClient

agent = AgentClient("${location.origin}", "${agent.agent_id}",
                    open("${agent.name}.pem").read())
agent.login("${dlg && dlg.delegation_id ? dlg.delegation_id : '<delegation_id>'}")
print(agent.call("${agent.allowed_tools[0]}", {}))`;
  $('resultCard').innerHTML = `
    <b>Agent <code>${esc(agent.name)}</code> created</b> &nbsp;<code>${esc(agent.agent_id)}</code>
    <button class="small" style="float:right" onclick="$('resultCard').classList.add('hidden')">Close</button>
    <div style="margin:6px 0">Tools: ${agent.allowed_tools.map(t=>`<span class="chip">${esc(t)}</span>`).join('')}</div>
    ${dlg ? (dlg.error ? `<div class="err">Delegation failed: ${esc(dlg.error)}</div>`
                        : `<div>Delegation for <b>${esc(dlg.user_id)}</b>: <code>${esc(dlg.delegation_id)}</code>, expires ${new Date(dlg.expires_at*1000).toLocaleString()}</div>`) : ''}
    <p class="warn">Save this private key now. It is shown only once and AgentPass does not keep it.</p>
    <pre>${esc(LAST_KEY)}</pre>
    <button onclick="navigator.clipboard.writeText(LAST_KEY)">Copy key</button>
    <button onclick="downloadKey()">Download ${esc(agent.name)}.pem</button>
    <p style="margin-bottom:0">Use it from Python:</p><pre>${esc(snippet)}</pre>`;
  $('resultCard').classList.remove('hidden');
}
function downloadKey(){
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([LAST_KEY], {type:'application/x-pem-file'}));
  a.download = LAST_NAME + '.pem'; a.click();
}
function ruleText(r){
  const p = [];
  if (r.max_amount) p.push('max ₹' + r.max_amount);
  if (r.require_approval_above) p.push('ask > ₹' + r.require_approval_above);
  if (r.budget) p.push('₹' + r.budget.amount + '/' + r.budget.period_days + 'd');
  if (r.require_approval) p.push('always ask');
  return p.join(', ');
}
async function load(){
  let a, p, l;
  try { [a, p, l] = await Promise.all([api('GET','/agents'), api('GET','/approvals'), api('GET','/audit?limit=100')]); }
  catch(e) { $('agents').innerHTML = `<tr><td class="err">${esc(e.message)}</td></tr>`; return; }
  const now = Date.now()/1000;
  $('agents').innerHTML = '<tr><th>Name</th><th>Status</th><th>Tools &amp; limits</th><th>Access for</th><th></th></tr>' +
   (a.agents.length ? a.agents.map(x => {
      const live = x.delegations.filter(d => !d.revoked && d.expires_at > now);
      return `<tr><td><b>${esc(x.name)}</b><br><code class="hint">${esc(x.id)}</code><br><span class="hint">${esc(x.purpose)}</span></td>
       <td class="${esc(x.status)}">${esc(x.status)}</td>
       <td>${x.allowed_tools.map(t => `<span class="chip">${esc(t)}${ruleText(x.rules[t]||{}) ? ' · ' + esc(ruleText(x.rules[t])) : ''}</span>`).join('<br>')}</td>
       <td>${live.length ? live.map(d => `${esc(d.user_id)} <span class="hint">until ${new Date(d.expires_at*1000).toLocaleString()}</span>`).join('<br>') : '<span class="hint">none</span>'}</td>
       <td>${x.status==='active' ? `<button class="small" onclick="if(confirm('Revoke ${esc(x.name)}? Its tokens stop working immediately.')) post('/agents/${esc(x.id)}/revoke')">Revoke</button>` : ''}</td></tr>`;
    }).join('') : '<tr><td colspan=5 class="empty">No agents yet. Click <b>+ Add agent</b>, or run <code>./run.sh demo --url ' + esc(location.origin) + '</code></td></tr>');
  $('approvals').innerHTML = '<tr><th>Agent</th><th>Tool</th><th>Args</th><th>Why</th><th></th></tr>' +
   (p.approvals.length ? p.approvals.map(x => `<tr><td>${esc(x.agent_name)}</td><td>${esc(x.tool)}</td><td><code>${esc(JSON.stringify(x.args))}</code></td><td>${esc(x.reason)}</td>
     <td><button class="small" onclick="post('/approvals/${esc(x.id)}/approve')">Approve</button> <button class="small" onclick="post('/approvals/${esc(x.id)}/deny')">Deny</button></td></tr>`).join('')
     : '<tr><td colspan=5 class="empty">None</td></tr>');
  $('audit').innerHTML = '<tr><th>Time</th><th>Agent</th><th>User</th><th>Action</th><th>Decision</th><th>Reason</th></tr>' +
   (l.events.length ? l.events.map(e => `<tr><td>${new Date(e.ts*1000).toLocaleTimeString()}</td><td>${esc(e.agent_name)}</td><td>${esc(e.user_id)}</td><td>${esc(e.action)}</td><td class="${esc(e.decision)}">${esc(e.decision)}</td><td>${esc(e.reason)}</td></tr>`).join('')
     : '<tr><td colspan=6 class="empty">No events yet</td></tr>');
}
loadTools(); load(); setInterval(load, 3000);
</script></body></html>"""
