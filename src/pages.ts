// Server-rendered pages on the app host: the viewer shell (/a/:id), the gallery (/), and the
// sign-in screens. Every page carries a per-response nonce CSP; scripts only call /api.
import { canAdmin, canWrite, describeMode, isAdmin, orgPolicy } from "./authz";
import { contentOrigin } from "./content";
import { shellCsp } from "./csp";
import { randomToken } from "./crypto";
import type { Artifact, Env } from "./env";

export const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

const STYLE = `
:root{--bg:#f7f6f3;--panel:#fff;--ink:#1d1c1a;--muted:#6b6862;--line:#e3e0da;--accent:#2f5d50;--accent-ink:#fff;--warn:#9a3b1c;--chip:#efece6;--shadow:0 8px 30px rgba(0,0,0,.12)}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--panel:#1f1f1d;--ink:#ecebe8;--muted:#a19d95;--line:#33322f;--accent:#7fbfa9;--accent-ink:#10201b;--warn:#f0936f;--chip:#2a2927;--shadow:0 8px 30px rgba(0,0,0,.5)}}
*{box-sizing:border-box}html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--ink);font:14px/1.45 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--accent)}button,input,textarea,select{font:inherit;color:inherit}
button{cursor:pointer;border:1px solid var(--line);background:var(--panel);border-radius:8px;padding:6px 12px}
button.primary{background:var(--accent);color:var(--accent-ink);border-color:var(--accent)}
button:disabled{opacity:.5;cursor:default}
input[type=text],input[type=email],textarea{width:100%;border:1px solid var(--line);background:var(--bg);border-radius:8px;padding:8px}
.muted{color:var(--muted)}.chip{background:var(--chip);border-radius:999px;padding:2px 9px;font-size:12px;white-space:nowrap}
.bar{display:flex;align-items:center;gap:10px;padding:8px 16px;border-bottom:1px solid var(--line);background:var(--panel);min-height:52px}
.bar .title{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.bar .grow{flex:1;min-width:0;display:flex;flex-direction:column}
.bar .sub{font-size:12px}
.brand{font-weight:700;text-decoration:none;color:var(--ink);letter-spacing:-.01em}
.dialog{position:fixed;inset:0;background:rgba(0,0,0,.35);display:none;align-items:flex-start;justify-content:center;padding:60px 16px;z-index:10}
.dialog.open{display:flex}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow);width:100%;max-width:480px;padding:20px}
.card h2{margin:0 0 12px;font-size:16px}
.opt{display:flex;gap:10px;align-items:flex-start;padding:8px;border-radius:8px}
.opt:hover{background:var(--chip)}.opt input{margin-top:3px}
.row{display:flex;gap:8px;align-items:center}.row.end{justify-content:flex-end}
.field{margin:12px 0}.field>label:not(.opt){display:block;font-size:12px;color:var(--muted);margin-bottom:4px}
.err{color:var(--warn);font-size:13px;min-height:1em}
.toast{position:fixed;bottom:16px;left:50%;transform:translateX(-50%);background:var(--ink);color:var(--bg);padding:8px 14px;border-radius:8px;display:none;z-index:20}
@media (max-width:640px){.hide-sm{display:none}.bar{flex-wrap:wrap;gap:6px;padding:8px 12px}.bar .grow{flex-basis:100%}.bar button{padding:5px 10px;font-size:13px}}
`;

function page(env: Env, opts: { title: string; body: string; script?: string; frameOrigin?: string | null }) {
  const nonce = randomToken(16);
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>${esc(opts.title)}</title>
<style nonce="${nonce}">${STYLE}</style></head><body>${opts.body}
${opts.script ? `<script nonce="${nonce}">${opts.script}</script>` : ""}</body></html>`;
  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy": shellCsp(nonce, opts.frameOrigin ?? null),
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    },
  });
}

// Shared client helpers: api() sends JSON with the same-origin Origin header browsers add anyway.
const CLIENT = `
const $=(s,r=document)=>r.querySelector(s);
async function api(path,opts={}){const r=await fetch('/api'+path,{credentials:'same-origin',...opts,headers:{...(opts.body&&!(opts.body instanceof FormData)?{'Content-Type':'application/json'}:{}),...(opts.headers||{})}});const t=await r.text();let j;try{j=JSON.parse(t)}catch{j={error:t}}if(!r.ok)throw new Error(j.error||('HTTP '+r.status));return j}
function toast(m){const t=$('#toast');t.textContent=m;t.style.display='block';clearTimeout(toast.h);toast.h=setTimeout(()=>t.style.display='none',2200)}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c])}
`;

export function viewerPage(env: Env, a: Artifact, email: string | null, version: number, src: string) {
  const policy = orgPolicy(env);
  const owner = canAdmin(policy, a, email);
  const editor = canWrite(policy, a, email);
  const boot = JSON.stringify({ id: a.id, version, live: a.live_version, owner, editor, email, signedIn: !!email });
  const body = `
<div style="display:flex;flex-direction:column;height:100%">
  <div class="bar">
    <a class="brand hide-sm" href="/">share</a>
    <div class="grow"><span class="title">${esc(a.title)}</span>
      <span class="sub muted">${esc(a.owner)} · <span id="ver">v${version}</span>${editor ? ` · <span class="chip">${esc(describeMode(a.read_mode, env.ORG_NAME))}</span>` : ""}</span></div>
    <button id="commentsBtn" title="Comments">Comments</button>
    <a id="full" class="hide-sm" href="${esc(src)}" target="_blank" rel="noopener noreferrer"><button>Full page</button></a>
    ${owner ? `<button id="shareBtn" class="primary">Share</button>` : `<button id="copyBtn">Copy link</button>`}
    ${email ? "" : `<a href="/login?next=${encodeURIComponent(`/a/${a.id}`)}"><button>Sign in</button></a>`}
  </div>
  <div style="flex:1;display:flex;min-height:0">
    <iframe id="frame" src="${esc(src)}" title="${esc(a.title)}" style="flex:1;border:0;background:#fff;min-width:0"
      sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox allow-modals allow-downloads"
      allow="clipboard-write; fullscreen" referrerpolicy="no-referrer"></iframe>
    <aside id="comments" style="display:none;width:320px;max-width:85vw;border-left:1px solid var(--line);background:var(--panel);flex-direction:column">
      <div class="bar"><b class="grow">Comments</b><button id="closeComments">×</button></div>
      <div id="clist" style="flex:1;overflow:auto;padding:12px"></div>
      <form id="cform" style="padding:12px;border-top:1px solid var(--line);display:${email ? "block" : "none"}">
        <textarea id="cbody" rows="3" placeholder="Add a comment"></textarea>
        <div class="row end" style="margin-top:6px"><button class="primary">Post</button></div>
      </form>
      ${email ? "" : `<p class="muted" style="padding:12px">Sign in to comment.</p>`}
    </aside>
  </div>
</div>
${owner ? shareDialog(env) : ""}
<div id="toast" class="toast"></div>`;

  const script = `${CLIENT}
const B=${boot};
const link=location.origin+'/a/'+B.id;
async function copy(){await navigator.clipboard.writeText(link);toast('Link copied')}
$('#copyBtn')?.addEventListener('click',copy);

// Live updates: viewers following live see a new publish within ~15s, as on claude.ai.
let shown=B.version;
setInterval(async()=>{if(document.hidden)return;try{const h=await api('/artifacts/'+B.id+'/head');if(h.version!==shown){const f=await api('/artifacts/'+B.id+'/frame');shown=f.version;$('#frame').src=f.src;$('#full').href=f.src;$('#ver').textContent='v'+f.version;toast('Updated to v'+f.version)}}catch{}},15000);

// Comments
async function loadComments(){const {comments}=await api('/artifacts/'+B.id+'/comments');$('#clist').innerHTML=comments.length?comments.map(c=>'<div style="margin-bottom:12px;'+(c.resolved?'opacity:.5':'')+'"><div class="muted" style="font-size:12px">'+esc(c.author)+' · v'+c.ver+' · '+new Date(c.created_at).toLocaleString()+'</div><div style="white-space:pre-wrap">'+esc(c.body)+'</div>'+(B.editor&&!c.resolved?'<button data-resolve="'+c.id+'" style="font-size:12px;padding:2px 8px;margin-top:4px">Resolve</button>':'')+'</div>').join(''):'<p class="muted">No comments yet.</p>'}
$('#commentsBtn').addEventListener('click',()=>{const c=$('#comments');const open=c.style.display==='none';c.style.display=open?'flex':'none';if(open)loadComments()});
$('#closeComments').addEventListener('click',()=>$('#comments').style.display='none');
$('#clist').addEventListener('click',async e=>{const id=e.target.dataset?.resolve;if(!id)return;await api('/artifacts/'+B.id+'/comments/'+id,{method:'PATCH',body:JSON.stringify({resolved:true})});loadComments()});
$('#cform').addEventListener('submit',async e=>{e.preventDefault();const body=$('#cbody').value.trim();if(!body)return;try{await api('/artifacts/'+B.id+'/comments',{method:'POST',body:JSON.stringify({body,version:shown})});$('#cbody').value='';loadComments()}catch(x){toast(x.message)}});
${owner ? SHARE_SCRIPT : ""}`;

  return page(env, { title: a.title, body, script, frameOrigin: contentOrigin(env, a.id) });
}

const shareDialog = (env: Env) => `
<div id="share" class="dialog" role="dialog" aria-modal="true" aria-labelledby="shareTitle"><div class="card">
  <h2 id="shareTitle">Share</h2>
  <div id="modes">
    <label class="opt"><input type="radio" name="mode" value="owner"><div><b>Only you</b><div class="muted">Private. Editors you add below can still open it.</div></div></label>
    <label class="opt"><input type="radio" name="mode" value="users"><div><b>Specific people</b><div class="muted">They sign in on the sign-in page. Their email or domain must be allowed to sign in.</div></div></label>
    <label class="opt"><input type="radio" name="mode" value="org"><div><b>${esc(env.ORG_NAME)}</b><div class="muted">Anyone signed in as a member of ${esc(env.ORG_NAME)}.</div></div></label>
    <label class="opt"><input type="radio" name="mode" value="public"><div><b>Anyone with the link</b><div class="muted">No sign-in. Treat the link as public.</div></div></label>
  </div>
  <div class="field" id="usersField"><label for="users">People who can view (emails)</label><textarea id="users" rows="2" placeholder="name@example.com, …"></textarea></div>
  <div class="field"><label for="editors">Editors who can publish new versions (emails)</label><input id="editors" type="text" placeholder="optional"></div>
  <div class="field"><label>Viewers see</label>
    <label class="opt"><input type="radio" name="pin" value="live"><div><b>Live</b><div class="muted">Every new publish, as soon as it lands.</div></div></label>
    <label class="opt"><input type="radio" name="pin" value="current"><div><b>This version only</b><div class="muted" id="pinNote">Pin to the current version; later publishes stay private until you move the pin.</div></div></label>
  </div>
  <div class="err" id="shareErr"></div>
  <div class="row"><button id="copyLink">Copy link</button><span style="flex:1"></span><button id="shareCancel">Cancel</button><button id="shareSave" class="primary">Save</button></div>
</div></div>`;

const SHARE_SCRIPT = `
let S=null;
async function openShare(){const a=await api('/artifacts/'+B.id);S=a.sharing;document.querySelector('input[name=mode][value='+S.mode+']').checked=true;document.querySelector('input[name=pin][value='+(S.pinned_version===null?'live':'current')+']').checked=true;$('#pinNote').textContent=S.pinned_version===null?'Pin to v'+a.live_version+'; later publishes stay private until you move the pin.':'Pinned to v'+S.pinned_version+(S.pinned_version!==a.live_version?' (live is v'+a.live_version+'). Choose Live, save, then pin again to move it.':'.');$('#users').value=S.users.join(', ');$('#editors').value=S.editors.join(', ');syncUsers();$('#shareErr').textContent='';$('#share').classList.add('open')}
function syncUsers(){$('#usersField').style.display=document.querySelector('input[name=mode]:checked')?.value==='users'?'block':'none'}
$('#modes').addEventListener('change',syncUsers);
$('#shareBtn').addEventListener('click',openShare);
$('#shareCancel').addEventListener('click',()=>$('#share').classList.remove('open'));
$('#copyLink').addEventListener('click',copy);
$('#share').addEventListener('click',e=>{if(e.target.id==='share')$('#share').classList.remove('open')});
$('#shareSave').addEventListener('click',async()=>{const mode=document.querySelector('input[name=mode]:checked').value;const pinSel=document.querySelector('input[name=pin]:checked').value;const pin=pinSel==='live'?'live':(S.pinned_version!==null?S.pinned_version:'current');try{await api('/artifacts/'+B.id+'/sharing',{method:'PUT',body:JSON.stringify({mode,users:$('#users').value,editors:$('#editors').value,pin})});$('#share').classList.remove('open');toast('Sharing saved');setTimeout(()=>location.reload(),600)}catch(x){$('#shareErr').textContent=x.message}});
`;

export function galleryPage(env: Env, email: string) {
  const admin = isAdmin(orgPolicy(env), email);
  const body = `
<div class="bar"><span class="brand">share</span><span class="grow"></span><span class="muted hide-sm">${esc(email)}</span><a href="/logout"><button>Sign out</button></a></div>
<main style="max-width:960px;margin:0 auto;padding:20px 16px">
  <section id="drop" style="border:2px dashed var(--line);border-radius:14px;padding:22px;text-align:center;background:var(--panel)">
    <b>Publish a page</b>
    <p class="muted" style="margin:6px 0 12px">Drop an .html file or a folder with an index.html. It starts private.</p>
    <div class="row" style="justify-content:center;flex-wrap:wrap">
      <input id="ptitle" type="text" placeholder="Title" style="max-width:280px">
      <label><button type="button" id="pickFile">Choose file</button><input id="file" type="file" accept=".html,.htm" hidden></label>
      <label><button type="button" id="pickDir">Choose folder</button><input id="dir" type="file" webkitdirectory hidden></label>
    </div>
    <div class="err" id="pubErr"></div>
  </section>
  <h3 style="margin:24px 0 8px">Yours and shared with you</h3>
  <div id="list" class="muted">Loading…</div>
  <h3 style="margin:28px 0 8px">Tokens for the CLI and agents</h3>
  <p class="muted" style="margin-top:0">For <code>lshare</code> on the mini or the laptop. A token publishes as you.</p>
  <div class="row" style="max-width:640px;flex-wrap:wrap"><input id="tlabel" type="text" placeholder="label, e.g. agents" style="max-width:240px">${
    admin ? `<input id="tas" type="email" placeholder="publish as (blank = you)" style="max-width:280px">` : ""
  }<button id="tnew">Create</button></div>
  <pre id="tshow" style="display:none;background:var(--chip);padding:10px;border-radius:8px;overflow:auto"></pre>
  <div id="tlist" class="muted" style="margin-top:8px"></div>
</main>
<div id="toast" class="toast"></div>`;

  const script = `${CLIENT}
const ME=${JSON.stringify(email).replace(/</g, "\\u003c")};
const MODES={owner:'Only you',users:'Specific people',org:${JSON.stringify(env.ORG_NAME).replace(/</g, "\\u003c")},public:'Anyone with the link'};
async function load(){const {artifacts}=await api('/artifacts');$('#list').classList.remove('muted');$('#list').innerHTML=artifacts.length?'<div style="display:grid;gap:8px">'+artifacts.map(a=>'<a href="/a/'+a.id+'" style="text-decoration:none;color:inherit"><div style="background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px;display:flex;gap:10px;align-items:center"><div style="flex:1;min-width:0"><div style="font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(a.title)+'</div><div class="muted" style="font-size:12px">'+(a.role==='owner'?'':esc(a.owner)+' · ')+'v'+a.live_version+' · '+new Date(a.updated_at).toLocaleString()+'</div></div>'+(a.sharing?'<span class="chip">'+MODES[a.sharing.mode]+'</span>':'<span class="chip">'+a.role+'</span>')+'</div></a>').join('')+'</div>':'<p>Nothing yet.</p>'}
async function publish(files){$('#pubErr').textContent='';const fd=new FormData();let strip='';if(files.length&&files[0].webkitRelativePath){strip=files[0].webkitRelativePath.split('/')[0]+'/'}for(const f of files){const p=(f.webkitRelativePath||f.name).slice(strip.length&&(f.webkitRelativePath||'').startsWith(strip)?strip.length:0);if(p.split('/').some(s=>s.startsWith('.')))continue;fd.append('file',f,files.length===1&&!f.webkitRelativePath?'index.html':p)}const title=$('#ptitle').value.trim()||(files.length===1?files[0].name.replace(/\\.html?$/,''):strip.replace(/\\/$/,''))||'Untitled';fd.append('title',title);try{const a=await api('/artifacts',{method:'POST',body:fd});location.href='/a/'+a.id}catch(x){$('#pubErr').textContent=x.message}}
$('#pickFile').addEventListener('click',()=>$('#file').click());$('#pickDir').addEventListener('click',()=>$('#dir').click());
$('#file').addEventListener('change',e=>publish([...e.target.files]));$('#dir').addEventListener('change',e=>publish([...e.target.files]));
const drop=$('#drop');drop.addEventListener('dragover',e=>{e.preventDefault();drop.style.borderColor='var(--accent)'});drop.addEventListener('dragleave',()=>drop.style.borderColor='');
drop.addEventListener('drop',e=>{e.preventDefault();drop.style.borderColor='';const fs=[...e.dataTransfer.files].filter(f=>/\\.html?$/i.test(f.name));if(fs.length!==1){$('#pubErr').textContent='Drop one .html file, or use Choose folder for a multi-file page.';return}publish(fs)});
async function tokens(){const {tokens}=await api('/tokens');$('#tlist').innerHTML=tokens.map(t=>'<div class="row" style="padding:4px 0"><code>'+t.id+'</code><span style="flex:1">'+esc(t.label)+(t.owner!==ME?' <span class="chip">as '+esc(t.owner)+'</span>':'')+' <span class="muted">· last used '+(t.last_used?new Date(t.last_used).toLocaleString():'never')+'</span></span><button data-revoke="'+t.id+'">Revoke</button></div>').join('')}
$('#tnew').addEventListener('click',async()=>{try{const r=await api('/tokens',{method:'POST',body:JSON.stringify({label:$('#tlabel').value,as:($('#tas')?.value||'').trim()||undefined})});$('#tshow').style.display='block';$('#tshow').textContent='Shown once. Store it in 1Password, then set LSHARE_TOKEN:\\n'+r.token;tokens()}catch(x){toast(x.message)}});
$('#tlist').addEventListener('click',async e=>{const id=e.target.dataset?.revoke;if(!id)return;await api('/tokens/'+id,{method:'DELETE'});tokens()});
load();tokens();`;

  return page(env, { title: "share", body, script });
}

export function messagePage(env: Env, title: string, message: string, action?: { href: string; label: string }) {
  return page(env, {
    title,
    body: `<main style="max-width:480px;margin:80px auto;padding:0 16px"><h2>${esc(title)}</h2><p class="muted">${esc(message)}</p>${
      action ? `<a href="${esc(action.href)}"><button class="primary">${esc(action.label)}</button></a>` : ""
    }</main>`,
  });
}

// wrangler dev only (DEV_LOGIN=1): stands in for the Access-protected login host.
export function devLoginPage(env: Env, next: string) {
  return page(env, {
    title: "Dev sign-in",
    body: `<main style="max-width:420px;margin:80px auto;padding:0 16px"><h2>Dev sign-in</h2>
<p class="muted">wrangler dev only. Production signs in through Cloudflare Access.</p>
<form method="post" action="/login/dev"><input type="hidden" name="next" value="${esc(next)}">
<div class="field"><label for="email">Email</label><input id="email" name="email" type="email" required></div>
<button class="primary">Sign in</button></form></main>`,
  });
}
