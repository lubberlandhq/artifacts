// Server-rendered pages on the app host: the viewer shell (/a/:id), the gallery (/), and the
// sign-in screens. Every page carries a per-response nonce CSP; scripts only call /api.
import { canAdmin, canPublish, canWrite, describeMode, isAdmin, orgPolicy } from "./authz";
import { contentOrigin } from "./content";
import { shellCsp } from "./csp";
import { randomToken } from "./crypto";
import type { Artifact, Env } from "./env";

export const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

const STYLE = `
:root{color-scheme:light dark;--bg:#f5f5f4;--panel:#fff;--ink:#18181b;--muted:#63636b;--line:#e1e1e3;--accent:#18181b;--accent-ink:#fff;--pin:#d93025;--warn:#b3261e;--danger:#b3261e;--chip:#ececee;--scrim:rgba(0,0,0,.45);--shadow:0 12px 40px rgba(0,0,0,.16);--edge:color-mix(in srgb,var(--line) 62%,var(--muted));--hover:color-mix(in srgb,var(--chip) 50%,var(--panel))}
@media (prefers-color-scheme:dark){:root{--bg:#0e0e0f;--panel:#19191b;--ink:#ededee;--muted:#a0a0a8;--line:#2d2d31;--accent:#ededee;--accent-ink:#111112;--pin:#ff6b5e;--warn:#ff8f80;--danger:#d93025;--chip:#2c2c30;--scrim:rgba(0,0,0,.65);--shadow:0 12px 40px rgba(0,0,0,.6)}}
*{box-sizing:border-box}html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--ink);font:14px/1.45 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;accent-color:var(--accent);-webkit-font-smoothing:antialiased}
::selection{background:color-mix(in srgb,var(--ink) 16%,transparent)}
a{color:var(--accent)}button,input,textarea,select{font:inherit;color:inherit}
h2{letter-spacing:-.01em}code{font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace}
button{cursor:pointer;border:1px solid var(--edge);background:var(--panel);border-radius:8px;padding:6px 12px;min-height:34px;font-weight:500;white-space:nowrap;transition:background-color .12s ease-out,border-color .12s ease-out,color .12s ease-out}
a>button{color:var(--ink)}
button:hover:not(:disabled){background:var(--chip)}
button.on{background:var(--chip);border-color:var(--muted)}
button.primary{background:var(--accent);color:var(--accent-ink);border-color:var(--accent)}
button.primary:hover:not(:disabled){background:color-mix(in srgb,var(--accent) 82%,var(--panel));border-color:color-mix(in srgb,var(--accent) 82%,var(--panel))}
button.ghost{border-color:transparent;background:transparent;color:var(--muted)}
button.ghost:hover:not(:disabled){background:var(--chip);color:var(--ink)}
button.ghost[data-delete]:hover:not(:disabled),button.ghost[data-revoke]:hover:not(:disabled){color:var(--warn)}
button.sm{padding:3px 9px;min-height:28px;font-size:12.5px}
button.danger{background:var(--danger);color:#fff;border-color:var(--danger)}
button.danger:hover:not(:disabled){background:color-mix(in srgb,var(--danger) 86%,#000);border-color:color-mix(in srgb,var(--danger) 86%,#000)}
button:disabled{opacity:.5;cursor:default}
:focus-visible{outline:2px solid color-mix(in srgb,var(--accent) 70%,transparent);outline-offset:2px}
input[type=text],input[type=email],textarea{width:100%;border:1px solid var(--edge);background:var(--panel);border-radius:8px;padding:6px 10px;min-height:34px;transition:border-color .12s ease-out}
textarea{display:block;padding:8px 10px;resize:vertical}
input[type=text]:hover,input[type=email]:hover,textarea:hover{border-color:var(--muted)}
input::placeholder,textarea::placeholder{color:var(--muted);opacity:.8}
.muted{color:var(--muted)}.chip{display:inline-block;background:var(--chip);border-radius:999px;padding:2px 9px;font-size:12px;line-height:1.45;white-space:nowrap}
.bar{display:flex;align-items:center;gap:12px;padding:8px 20px;border-bottom:1px solid var(--line);background:var(--panel);min-height:56px}
.bar.fit{padding-inline:max(16px,calc((100% - 928px)/2))}
.bar .title{font-weight:600;line-height:1.3;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.bar .grow{flex:1;min-width:0;display:flex;flex-direction:column;gap:1px}
.bar .sub{font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-variant-numeric:tabular-nums}
.bar .sub .chip{font-size:11px;padding:1px 8px}
.bar .vr{flex:none;width:1px;height:24px;background:var(--line);margin:0 4px}
aside .bar{padding:8px 12px 8px 16px;min-height:48px}
.brand{font-size:15px;font-weight:700;text-decoration:none;color:var(--ink);letter-spacing:-.01em;display:inline-flex;align-items:center;gap:8px}
.brand svg{width:22px;height:22px;flex:none}.mk-s{fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}.mk-a{fill:var(--pin)}
.dialog{position:fixed;inset:0;background:var(--scrim);display:none;align-items:flex-start;justify-content:center;padding:min(7vh,64px) 16px 24px;overflow:auto;z-index:10}
.dialog.open{display:flex}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow);width:100%;max-width:480px;padding:24px}
.card h2{margin:0 0 12px;font-size:17px}
.card>.row:last-child{margin-top:18px}#shareErr:empty{display:none}
.opt{display:flex;gap:10px;align-items:flex-start;padding:8px 10px;border-radius:8px;cursor:pointer}
.opt:hover{background:var(--hover)}.opt:has(input:checked){background:var(--chip)}.opt input{flex:none;width:15px;height:15px;margin:3px 0 0}
.row{display:flex;gap:8px;align-items:center}.row.end{justify-content:flex-end}
.field{margin:14px 0}.field>label:not(.opt){display:block;font-size:12px;font-weight:600;color:var(--muted);margin-bottom:6px}
#share .field{border-top:1px solid var(--line);padding-top:12px}#modes,#share .field .opt{margin-inline:-10px}
.err{color:var(--warn);font-size:13px;min-height:1em}
.toast{position:fixed;bottom:16px;left:50%;transform:translateX(-50%);background:var(--ink);color:var(--bg);padding:8px 14px;border-radius:8px;box-shadow:var(--shadow);display:none;z-index:20}
[hidden]{display:none!important}
.sec{margin:32px 0 10px;font-size:18px;font-weight:650}
.drop{display:flex;flex-wrap:wrap;align-items:center;gap:12px 24px;border:1.5px dashed var(--edge);border-radius:12px;padding:18px 20px;background:var(--panel);transition:border-color .12s ease-out,background-color .12s ease-out}
.drop.over{border-color:var(--accent);background:var(--hover)}
.dtext{flex:1 1 300px;min-width:0}.dtext b{display:block;font-size:15px}.dtext p{margin:2px 0 0;font-size:13px}
.dctl{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.dctl input[type=text]{width:190px}
#pubErr{flex-basis:100%}#pubErr:empty{display:none}
.alist{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.acard{position:relative;display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center;padding:12px 12px 12px 16px;border-top:1px solid var(--line);transition:background-color .12s ease-out}
.acard:first-child,.trow:first-child{border-top:0}
.acard:hover{background:var(--hover)}
.amain{flex:1;min-width:0;text-decoration:none;color:inherit}.amain::after{content:"";position:absolute;inset:0}
.atitle{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.atitle .chip{font-weight:400;margin-left:4px}
.ameta{font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.achip{flex:none;min-width:136px}.achip.end{min-width:0}
.aact{position:relative;z-index:1;display:flex;gap:2px}
.trow{display:flex;align-items:center;gap:12px;padding:10px 12px 10px 16px;border-top:1px solid var(--line)}
.tmain{flex:1;min-width:0}
.citem{padding:12px 0;border-top:1px solid var(--line)}.citem:first-child{border-top:0;padding-top:0}.citem.done{opacity:.55}
.cmeta{font-size:12px;color:var(--muted);margin-bottom:2px}.cmeta b{color:var(--ink);font-weight:600}.cbody{white-space:pre-wrap}
.solo{max-width:440px;margin:clamp(32px,11vh,120px) auto 32px;padding:28px;background:var(--panel);border:1px solid var(--line);border-radius:12px}
.solo h2{margin:0 0 8px;font-size:22px}.solo p{margin:0 0 16px}.solo .field{margin:0 0 16px}
.solo button{min-height:38px;padding:8px 16px}
.solo .code{font:600 22px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.08em}
#user_code{font:600 18px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.12em;min-height:44px}
@media (max-width:640px){.hide-sm{display:none}
.bar{flex-wrap:wrap;gap:8px 10px;padding:8px 14px}.bar.fit{padding-inline:14px}
.brand.mini .wm{display:none}.bar .grow:has(.title){flex:1 1 calc(100% - 40px)}
.bar:has(.title)>button,.bar:has(.title)>a{flex:1}.bar:has(.title)>a>button{width:100%}
button{min-height:40px}button.sm{min-height:36px;padding:6px 12px;font-size:13px}
input[type=text],input[type=email],textarea{font-size:16px;min-height:44px}
.dctl{width:100%}.dctl input[type=text]{width:100%}.dctl label{flex:1}.dctl label button{width:100%}
.amain{flex-basis:100%}.achip{min-width:0}.aact{margin-left:auto}
.dialog{padding-top:24px}.solo{margin:20px 14px;padding:22px}.solo button.primary{width:100%}}
`;

// The Tack mark: a plain sheet hanging at a tilt from one tack. The pin sits inside the sheet, not on
// its top edge, and there are no text lines, so it doesn't read as a clipboard at small sizes. Drawn on a 24px grid so it reads at favicon size.
const MARK_SHAPES = `<rect class="mk-s" x="5" y="3.5" width="14" height="17.5" rx="1.8" transform="rotate(9 12 8)"/><circle class="mk-a" cx="12" cy="8" r="2.9"/>`;
const MARK = `<svg viewBox="0 0 24 24" aria-hidden="true">${MARK_SHAPES}</svg>`;
// Pages with no chrome of their own (messages, sign-in) still say whose they are and lead home.
const TOPBAR = `<div class="bar"><a class="brand" href="/">${MARK}<span class="wm">tack</span></a></div>`;
// The favicon can't see the page's tokens, so it carries both palettes itself.
const FAVICON = `data:image/svg+xml,${encodeURIComponent(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><style>.mk-s{fill:none;stroke:#18181b;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}.mk-a{fill:#d93025}@media (prefers-color-scheme:dark){.mk-s{stroke:#ededee}.mk-a{fill:#ff6b5e}}</style>${MARK_SHAPES}</svg>`,
)}`;

function page(env: Env, opts: { title: string; body: string; script?: string; frameOrigin?: string | null }) {
  const nonce = randomToken(16);
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>${esc(opts.title)}</title>
<link rel="icon" type="image/svg+xml" href="${FAVICON}">
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
async function api(path,opts={}){const r=await fetch('/api'+path,{credentials:'same-origin',...opts,headers:{...(opts.body&&!(opts.body instanceof FormData)?{'Content-Type':'application/json'}:{}),...(opts.headers||{})}});const t=await r.text();let j;try{j=JSON.parse(t)}catch{j={error:t}}if(!r.ok)throw Object.assign(new Error(j.error||('HTTP '+r.status)),{status:r.status});return j}
function toast(m){const t=$('#toast');t.textContent=m;t.style.display='block';clearTimeout(toast.h);toast.h=setTimeout(()=>t.style.display='none',2200)}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c])}
const when=d=>new Date(d).toLocaleString([],{dateStyle:'medium',timeStyle:'short'});
`;

export function viewerPage(env: Env, a: Artifact, email: string | null, version: number, src: string) {
  const policy = orgPolicy(env);
  const owner = canAdmin(policy, a, email);
  const editor = canWrite(policy, a, email);
  const boot = JSON.stringify({ id: a.id, version, live: a.live_version, owner, editor, email, signedIn: !!email });
  const body = `
<div style="display:flex;flex-direction:column;height:100%">
  <div class="bar">
    <a class="brand mini" href="/">${MARK}<span class="wm">tack</span></a><span class="vr hide-sm" aria-hidden="true"></span>
    <div class="grow"><span class="title">${esc(a.title)}</span>
      <span class="sub muted">${esc(a.owner)} · <span id="ver">v${version}</span>${editor ? ` · <span class="chip">${esc(describeMode(a.read_mode, env.ORG_NAME))}</span>` : ""}</span></div>
    <button id="commentsBtn" title="Comments" aria-pressed="false">Comments</button>
    <a id="full" class="hide-sm" href="${esc(src)}" target="_blank" rel="noopener noreferrer"><button>Full page</button></a>
    ${owner ? `<button id="shareBtn" class="primary">Share</button>` : `<button id="copyBtn">Copy link</button>`}
    ${email ? "" : `<a href="/login?next=${encodeURIComponent(`/a/${a.id}`)}"><button>Sign in</button></a>`}
  </div>
  <div style="flex:1;display:flex;min-height:0">
    <iframe id="frame" src="${esc(src)}" title="${esc(a.title)}" style="flex:1;border:0;background:#fff;min-width:0"
      sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox allow-modals allow-downloads"
      allow="clipboard-write; fullscreen" referrerpolicy="no-referrer"></iframe>
    <aside id="comments" style="display:none;width:320px;max-width:85vw;border-left:1px solid var(--line);background:var(--panel);flex-direction:column">
      <div class="bar"><b class="grow">Comments</b><button id="closeComments" class="ghost" aria-label="Close comments">×</button></div>
      <div id="clist" style="flex:1;overflow:auto;padding:16px"></div>
      <form id="cform" style="padding:16px;border-top:1px solid var(--line);display:${email ? "block" : "none"}">
        <textarea id="cbody" rows="3" aria-label="Add a comment" placeholder="Add a comment"></textarea>
        <div class="row end" style="margin-top:8px"><button class="primary">Post</button></div>
      </form>
      ${email ? "" : `<p class="muted" style="padding:16px;margin:0">Sign in to comment.</p>`}
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

// Live updates: viewers following live see a new publish within ~15s, as on claude.ai. If the artifact is
// deleted or unshared, the same poll gets 401/404 and reloads, so the open tab stops showing it.
let shown=B.version;
setInterval(async()=>{if(document.hidden)return;try{const h=await api('/artifacts/'+B.id+'/head');if(h.version!==shown){const f=await api('/artifacts/'+B.id+'/frame');shown=f.version;$('#frame').src=f.src;$('#full').href=f.src;$('#ver').textContent='v'+f.version;toast('Updated to v'+f.version)}}catch(x){if(x.status===401||x.status===404)location.reload()}},15000);

// Comments
async function loadComments(){const {comments}=await api('/artifacts/'+B.id+'/comments');$('#clist').innerHTML=comments.length?comments.map(c=>'<div class="citem'+(c.resolved?' done':'')+'"><div class="cmeta"><b>'+esc(c.author)+'</b> · v'+c.ver+' · '+when(c.created_at)+'</div><div class="cbody">'+esc(c.body)+'</div>'+(B.editor&&!c.resolved?'<button class="sm" data-resolve="'+c.id+'" style="margin-top:6px">Resolve</button>':'')+'</div>').join(''):'<p class="muted">No comments yet.</p>'}
function showComments(open){$('#comments').style.display=open?'flex':'none';const b=$('#commentsBtn');b.classList.toggle('on',open);b.setAttribute('aria-pressed',open);if(open)loadComments()}
$('#commentsBtn').addEventListener('click',()=>showComments($('#comments').style.display==='none'));
$('#closeComments').addEventListener('click',()=>showComments(false));
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
  const policy = orgPolicy(env);
  const admin = isAdmin(policy, email);
  // Someone who can't publish gets no publish zone and no token form: both would only answer "not a publisher".
  const publisher = canPublish(policy, email);
  const body = `
<div class="bar fit"><span class="brand">${MARK}<span class="wm">tack</span></span><span class="grow"></span><span class="muted hide-sm">${esc(email)}</span><a href="/logout"><button class="ghost">Sign out</button></a></div>
<main style="max-width:960px;margin:0 auto;padding:20px 16px">
  ${
    publisher
      ? `<section id="drop" class="drop">
    <div class="dtext"><b>Publish a page</b><p class="muted">Drop an .html file or a folder with an index.html. It starts private.</p></div>
    <div class="dctl">
      <input id="ptitle" type="text" aria-label="Title" placeholder="Title">
      <label><button type="button" id="pickFile" class="primary">Choose file</button><input id="file" type="file" accept=".html,.htm" hidden></label>
      <label><button type="button" id="pickDir">Choose folder</button><input id="dir" type="file" webkitdirectory hidden></label>
    </div>
    <div class="err" id="pubErr"></div>
  </section>`
      : ""
  }
  <h2 class="sec"${publisher ? "" : ` style="margin-top:8px"`}>Yours and shared with you</h2>
  <div id="list" class="muted">Loading…</div>
  <section id="tsec"${publisher ? "" : " hidden"}>
    <h2 class="sec" style="margin-top:40px">Tokens for the CLI and agents</h2>
    ${
      publisher
        ? `<p class="muted" style="margin:0 0 12px">For <code>tack</code> on the mini or the laptop. A token publishes as you.</p>
    <div class="row" style="max-width:640px;flex-wrap:wrap"><input id="tlabel" type="text" aria-label="Token label" placeholder="label, e.g. agents" style="max-width:240px">${
      admin ? `<input id="tas" type="email" aria-label="Publish as" placeholder="publish as (blank = you)" style="max-width:280px">` : ""
    }<button id="tnew">Create</button></div>
    <div id="tnewbox" hidden><pre id="tshow" style="background:var(--chip);padding:10px;border-radius:8px;overflow:auto;margin-bottom:8px"></pre><button id="tcopy">Copy token</button></div>`
        : ""
    }
    <div id="tlist" style="margin-top:14px"></div>
    <div id="tmore" style="margin-top:8px"></div>
  </section>
</main>
<div id="ask" class="dialog" role="dialog" aria-modal="true" aria-labelledby="askTitle"><div class="card">
  <h2 id="askTitle"></h2>
  <p class="muted" id="askBody" style="margin:0 0 12px"></p>
  <div class="field" id="askField" hidden><label for="askInput">Title</label><input id="askInput" type="text" maxlength="200"></div>
  <div class="row end"><button id="askNo">Cancel</button><button id="askYes" class="primary"></button></div>
</div></div>
<div id="toast" class="toast"></div>`;

  const script = `${CLIENT}
const ME=${JSON.stringify(email).replace(/</g, "\\u003c")};
const PUB=${publisher};
const MODES={owner:'Only you',users:'Specific people',org:${JSON.stringify(env.ORG_NAME).replace(/</g, "\\u003c")},public:'Anyone with the link'};
const ROLES={viewer:'Shared with you'};
const day=d=>new Date(d).toLocaleDateString([],{dateStyle:'medium'});

// One dialog for confirming and for renaming. Resolves true (or the typed text), or null on cancel.
function ask(o){return new Promise(res=>{
  const d=$('#ask'),y=$('#askYes'),n=$('#askNo'),i=$('#askInput'),text=o.input!==undefined,prev=document.activeElement;
  $('#askTitle').textContent=o.title;$('#askBody').textContent=o.body||'';$('#askBody').hidden=!o.body;
  y.textContent=o.yes;y.className=o.danger?'danger':'primary';$('#askField').hidden=!text;i.value=o.input||'';
  d.classList.add('open');if(text){i.focus();i.select()}else n.focus();
  const done=v=>{d.classList.remove('open');d.onclick=d.onkeydown=y.onclick=n.onclick=null;prev&&prev.focus&&prev.focus();res(v)};
  y.onclick=()=>done(text?i.value.trim():true);n.onclick=()=>done(null);
  d.onclick=e=>{if(e.target===d)done(null)};
  d.onkeydown=e=>{if(e.key==='Escape')done(null);else if(e.key==='Enter'&&text){e.preventDefault();y.click()}};
})}

// Artifacts
let ARTS=[];
const card=a=>'<div class="acard"><a class="amain" href="/a/'+a.id+'"><div class="atitle">'+esc(a.title)+'</div><div class="ameta">'+(a.role==='owner'?'':esc(a.owner)+' · ')+'v'+a.live_version+' · '+when(a.updated_at)+'</div></a><span class="achip'+(a.role==='owner'?'':' end')+'"><span class="chip">'+(a.sharing?MODES[a.sharing.mode]:ROLES[a.role]||a.role)+'</span></span>'+(a.role==='owner'?'<span class="aact"><button class="sm ghost" data-rename="'+a.id+'">Rename</button><button class="sm ghost" data-delete="'+a.id+'">Delete</button></span>':'')+'</div>';
async function load(){ARTS=(await api('/artifacts')).artifacts;$('#list').classList.remove('muted');$('#list').innerHTML=ARTS.length?'<div class="alist">'+ARTS.map(card).join('')+'</div>':'<p>Nothing yet.</p>'}
$('#list').addEventListener('click',async e=>{
  const rid=e.target.dataset?.rename,did=e.target.dataset?.delete,a=ARTS.find(x=>x.id===(rid||did));if(!a)return;
  try{
    if(rid){const t=await ask({title:'Rename',yes:'Save',input:a.title});if(!t||t===a.title)return;await api('/artifacts/'+a.id,{method:'PATCH',body:JSON.stringify({title:t})});await load();toast('Renamed')}
    else{if(!await ask({title:'Delete “'+a.title+'”?',body:'The page, its versions and its comments are removed, and its link stops working. This can’t be undone.',yes:'Delete',danger:true}))return;await api('/artifacts/'+a.id,{method:'DELETE'});await load();toast('Deleted')}
  }catch(x){toast(x.message)}
});

// Publish. entries: [[path inside the page, File]]; name: the title when the Title box is empty.
async function publish(entries,name){if(publish.busy)return;$('#pubErr').textContent='';const fd=new FormData();for(const [p,f] of entries){if(p.split('/').some(s=>s.startsWith('.')))continue;fd.append('file',f,p)}fd.append('title',$('#ptitle').value.trim()||name||'Untitled');const btns=[$('#pickFile'),$('#pickDir')];publish.busy=true;btns.forEach(b=>b.disabled=true);try{const a=await api('/artifacts',{method:'POST',body:fd});location.href='/a/'+a.id}catch(x){publish.busy=false;btns.forEach(b=>b.disabled=false);$('#pubErr').textContent=x.message}}
const publishFile=f=>publish([['index.html',f]],f.name.replace(/\\.html?$/i,''));
const publishPicked=fs=>{const root=fs.length?fs[0].webkitRelativePath.split('/')[0]:'';return publish(fs.map(f=>[f.webkitRelativePath.slice(root.length+1),f]),root)};
// A dropped folder arrives as a directory entry, not as files: read it out, keeping paths relative to the folder.
const children=async d=>{const r=d.createReader(),all=[];for(;;){const b=await new Promise((ok,no)=>r.readEntries(ok,no));if(!b.length)return all;all.push(...b)}};
async function walk(d,prefix,out){for(const e of await children(d)){if(e.isDirectory)await walk(e,prefix+e.name+'/',out);else out.push([prefix+e.name,await new Promise((ok,no)=>e.file(ok,no))])}return out}
if(PUB){
  $('#pickFile').addEventListener('click',()=>$('#file').click());$('#pickDir').addEventListener('click',()=>$('#dir').click());
  $('#file').addEventListener('change',e=>e.target.files.length&&publishFile(e.target.files[0]));$('#dir').addEventListener('change',e=>publishPicked([...e.target.files]));
  const drop=$('#drop');drop.addEventListener('dragover',e=>{e.preventDefault();drop.classList.add('over')});drop.addEventListener('dragleave',()=>drop.classList.remove('over'));
  drop.addEventListener('drop',async e=>{e.preventDefault();drop.classList.remove('over');
    const ents=[...(e.dataTransfer.items||[])].map(i=>i.webkitGetAsEntry&&i.webkitGetAsEntry()).filter(Boolean);
    if(ents.length===1&&ents[0].isDirectory){try{await publish(await walk(ents[0],'',[]),ents[0].name)}catch(x){$('#pubErr').textContent=x.message}return}
    const fs=[...e.dataTransfer.files].filter(f=>/\\.html?$/i.test(f.name));
    if(ents.length>1||fs.length!==1){$('#pubErr').textContent='Drop one .html file or one folder.';return}
    publishFile(fs[0])});
}

// Tokens: the newest few, the rest behind "Show all".
let TOKS=[],allToks=false;const FEW=8;
const trow=t=>'<div class="trow"><div class="tmain"><div class="atitle">'+esc(t.label)+(t.owner!==ME?' <span class="chip">as '+esc(t.owner)+'</span>':'')+(t.scope?' <span class="chip">'+esc(t.scope)+' only</span>':'')+'</div><div class="ameta"><code>'+t.id+'</code> · last used '+(t.last_used?when(t.last_used):'never')+(t.expires_at?' · expires '+day(t.expires_at):'')+'</div></div><button class="sm ghost" data-revoke="'+t.id+'">Revoke</button></div>';
function showTokens(){$('#tsec').hidden=!PUB&&!TOKS.length;$('#tlist').className=TOKS.length?'alist':'';$('#tlist').innerHTML=(allToks?TOKS:TOKS.slice(0,FEW)).map(trow).join('');$('#tmore').innerHTML=!allToks&&TOKS.length>FEW?'<button id="tall">Show all '+TOKS.length+'</button>':''}
async function tokens(){TOKS=(await api('/tokens')).tokens;showTokens()}
$('#tmore').addEventListener('click',e=>{if(e.target.id==='tall'){allToks=true;showTokens()}});
let NEWTOK='';
$('#tnew')?.addEventListener('click',async()=>{try{const r=await api('/tokens',{method:'POST',body:JSON.stringify({label:$('#tlabel').value,as:($('#tas')?.value||'').trim()||undefined})});NEWTOK=r.token;$('#tnewbox').hidden=false;$('#tshow').textContent='Shown once. Store it in 1Password, then set TACK_TOKEN:\\n'+r.token;$('#tlabel').value='';await tokens()}catch(x){toast(x.message)}});
$('#tcopy')?.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(NEWTOK);toast('Token copied')}catch(x){toast(x.message)}});
$('#tlist').addEventListener('click',async e=>{const id=e.target.dataset?.revoke,t=TOKS.find(x=>x.id===id);if(!t)return;if(!await ask({title:'Revoke “'+t.label+'”?',body:'Anything using this token stops working right away.',yes:'Revoke',danger:true}))return;try{await api('/tokens/'+id,{method:'DELETE'});await tokens();toast('Revoked')}catch(x){toast(x.message)}});
load().catch(x=>{$('#list').textContent=x.message});tokens().catch(x=>{$('#tsec').hidden=false;$('#tlist').className='err';$('#tlist').textContent=x.message});`;

  return page(env, { title: "Tack", body, script });
}

export function messagePage(env: Env, title: string, message: string, action?: { href: string; label: string }) {
  return page(env, {
    title,
    body: `${TOPBAR}<main class="solo"><h2>${esc(title)}</h2><p class="muted">${esc(message)}</p>${
      action ? `<a href="${esc(action.href)}"><button class="primary">${esc(action.label)}</button></a>` : ""
    }</main>`,
  });
}

// wrangler dev only (DEV_LOGIN=1): stands in for the Access-protected login host.
export function devLoginPage(env: Env, next: string) {
  return page(env, {
    title: "Dev sign-in",
    body: `${TOPBAR}<main class="solo"><h2>Dev sign-in</h2>
<p class="muted">wrangler dev only. Production signs in through Cloudflare Access.</p>
<form method="post" action="/login/dev"><input type="hidden" name="next" value="${esc(next)}">
<div class="field"><label for="email">Email</label><input id="email" name="email" type="email" required></div>
<button class="primary">Sign in</button></form></main>`,
  });
}

// ---- Whiteboard share hub (src/whiteboard.ts) ------------------------------------------------

// /device: a signed-in person approves the computer where `whiteboard login` shows this code.
export function devicePage(env: Env, email: string, userCode: string | null) {
  const main = userCode
    ? `<h2>Sign in to Whiteboard</h2>
<p>Whiteboard on a computer is asking to sign in to ${esc(env.ORG_NAME)}'s Tack as <b>${esc(email)}</b>.</p>
<p class="muted">Approve only if you started this sign-in yourself and Whiteboard shows the same code.</p>
<p class="code">${esc(userCode)}</p>
<form method="post" action="/device"><input type="hidden" name="user_code" value="${esc(userCode)}">
<div class="row"><button class="primary">Approve</button><a href="/"><button type="button">Cancel</button></a></div></form>`
    : `<h2>Sign in to Whiteboard</h2>
<p class="muted">Enter the code Whiteboard shows.</p>
<form method="get" action="/device"><div class="field"><label for="user_code">Code</label>
<input id="user_code" name="user_code" type="text" autocomplete="off" autocapitalize="characters" required></div>
<button class="primary">Continue</button></form>`;
  const r = page(env, { title: "Sign in to Whiteboard", body: `${TOPBAR}<main class="solo">${main}</main>` });
  // The Approve form is a plain post, and under no-referrer a browser sends it with
  // `Origin: null`, which the same-site check on POST /device refuses. same-origin keeps the
  // real origin on this site's own posts and still tells other sites nothing.
  r.headers.set("Referrer-Policy", "same-origin");
  return r;
}

// /s/<capability>: a shared board. Anyone with the link reads it, so the page shows no account
// controls. `frameSrc` is null when no board viewer is registered on this server.
export function sharedBoardPage(
  env: Env,
  b: { title: string; sender: string; sharedAt: number; version: number; frameSrc: string | null; frameOrigin: string; openHref: string | null },
) {
  const title = b.title || "Whiteboard";
  const open = b.openHref ? `<a href="${esc(b.openHref)}"><button class="primary">Open in Whiteboard</button></a>` : "";
  const body = `
<div style="display:flex;flex-direction:column;height:100%">
  <div class="bar">
    <span class="brand mini">${MARK}<span class="wm">tack</span></span><span class="vr hide-sm" aria-hidden="true"></span>
    <div class="grow"><span class="title">${esc(title)}</span>
      <span class="sub muted">Shared by ${esc(b.sender)} · version ${b.version} · ${new Date(b.sharedAt).toISOString().slice(0, 10)}</span></div>
    ${open}
  </div>
  ${
    b.frameSrc
      ? `<iframe src="${esc(b.frameSrc)}" title="${esc(title)}" style="flex:1;border:0;min-height:0"
    sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox allow-modals allow-downloads"
    allow="clipboard-write; fullscreen" referrerpolicy="no-referrer"></iframe>`
      : `<main style="max-width:480px;margin:80px auto;padding:0 16px"><h2>${esc(title)}</h2>
  <p class="muted">This server has no browser view for boards yet. ${b.openHref ? "Open the board in Whiteboard Desktop." : ""}</p></main>`
  }
</div>`;
  const r = page(env, { title, body, frameOrigin: b.frameSrc ? b.frameOrigin : null });
  r.headers.set("X-Robots-Tag", "noindex");
  return r;
}
