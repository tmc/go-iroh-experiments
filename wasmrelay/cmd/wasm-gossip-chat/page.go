//go:build !js

package main

// page is the interactive gossip-chat UI. It defines irohOnEvent BEFORE running
// the wasm, instantiates the js/wasm node, and drives it via the irohSend /
// irohReady / irohNeighbors bridge the wasm installs on globalThis.
const page = `<!doctype html>
<html><head><meta charset="utf-8">
<title>go-iroh browser gossip chat — cross-tab, relay-only</title>
<script src="/wasm_exec.js"></script>
<style>
 :root{color-scheme:light dark}
 body{font:15px -apple-system,system-ui,sans-serif;margin:0;height:100vh;display:flex;flex-direction:column;color:#111;background:#fafafa}
 header{padding:.7rem 1rem;border-bottom:1px solid #ddd;background:#fff}
 header h1{font-size:1rem;margin:0 0 .25rem}
 header .meta{font-size:.8rem;color:#555;display:flex;gap:1rem;flex-wrap:wrap;align-items:center}
 .pill{background:#eef;border-radius:999px;padding:.1rem .55rem;font-variant-numeric:tabular-nums}
 .invite{font-size:.78rem;color:#333;margin-top:.4rem;display:none}
 .invite input{width:min(38rem,70vw);font:inherit;font-size:.75rem;padding:.2rem .4rem;border:1px solid #ccc;border-radius:6px}
 .invite button{font:inherit;font-size:.75rem;padding:.2rem .55rem;margin-left:.3rem;border-radius:6px;border:1px solid #ccc;background:#fff;cursor:pointer}
 #log{flex:1;overflow:auto;padding:1rem;display:flex;flex-direction:column;gap:.35rem}
 .m{max-width:70%;padding:.4rem .65rem;border-radius:10px;background:#fff;border:1px solid #e3e3e3}
 .m.self{align-self:flex-end;background:#dff0ff;border-color:#bcdfff}
 .m .who{font-size:.7rem;color:#666;margin-bottom:.1rem}
 .sys{align-self:center;font-size:.78rem;color:#777;font-style:italic}
 form{display:flex;gap:.5rem;padding:.7rem 1rem;border-top:1px solid #ddd;background:#fff}
 form input{flex:1;font:inherit;padding:.5rem .7rem;border:1px solid #ccc;border-radius:8px}
 form button{font:inherit;padding:.5rem 1rem;border-radius:8px;border:0;background:#0a67d0;color:#fff;cursor:pointer}
 form button:disabled{background:#9bb;cursor:default}
</style></head>
<body data-status="running" data-detail="loading">
<header>
 <h1>go-iroh in the browser — cross-tab gossip chat, relay-only (no UDP)</h1>
 <div class="meta">
  <span>status: <b id="st">loading wasm…</b></span>
  <span class="pill">id <span id="id">—</span></span>
  <span class="pill">neighbors <span id="nb">0</span></span>
  <span class="pill">topic <span id="tp">—</span></span>
 </div>
 <div class="invite" id="inv">
  Open this URL in another tab to join the room:
  <input id="invurl" readonly>
  <button id="copy" type="button">copy</button>
 </div>
</header>
<div id="log"></div>
<form id="f" autocomplete="off">
 <input id="in" placeholder="joining topic…" disabled>
 <button id="send" type="submit" disabled>send</button>
</form>
<script>
const $ = (id)=>document.getElementById(id);
const logEl = $("log");
let myId = "";

function short(s){ return s && s.length>12 ? s.slice(0,10)+"…" : s; }

function addMsg(who, text, self){
  const d = document.createElement("div");
  d.className = "m" + (self?" self":"");
  const w = document.createElement("div"); w.className="who"; w.textContent = self ? "you ("+short(myId)+")" : who;
  const t = document.createElement("div"); t.textContent = text;
  d.appendChild(w); d.appendChild(t);
  logEl.appendChild(d); logEl.scrollTop = logEl.scrollHeight;
}
function addSys(text){
  const d = document.createElement("div"); d.className="sys"; d.textContent=text;
  logEl.appendChild(d); logEl.scrollTop = logEl.scrollHeight;
}

// The wasm calls this for every gossip event. Defined BEFORE go.run().
globalThis.irohOnEvent = function(kind, from, text){
  if(kind==="self"){ myId = from; return; }
  if(kind==="msg"){
    // from is "endpointID|name"; a message echoed from ourselves is tagged self.
    const bar = from.indexOf("|");
    const fid = bar>=0 ? from.slice(0,bar) : from;
    const name = bar>=0 ? from.slice(bar+1) : "anon";
    addMsg(name+" ("+short(fid)+")", text, fid===myId);
    return;
  }
  if(kind==="up"){ addSys("neighbor up: "+short(from)); refreshNb(); return; }
  if(kind==="down"){ addSys("neighbor down: "+short(from)); refreshNb(); return; }
  if(kind==="status"){ addSys(text); return; }
  if(kind==="error"){ addSys("error: "+text); return; }
};

function refreshNb(){
  if(typeof globalThis.irohNeighbors!=="function") return;
  const n = globalThis.irohNeighbors();
  const pill = $("nb").parentElement;
  $("nb").textContent = n;
  // Color the pill by overlay health so self-healing is visible: red when
  // isolated (0), green when connected. The heal loop re-dials known peers when
  // this hits 0, so you can watch it recover.
  pill.style.background = n>0 ? "#e3f7e3" : "#fde2e2";
  pill.style.color = n>0 ? "#137013" : "#a11";
}
setInterval(refreshNb, 750);

// Watch data-status/-detail the wasm sets on <body>.
new MutationObserver(()=>{
  const s = document.body.getAttribute("data-status");
  const d = document.body.getAttribute("data-detail")||"";
  $("st").textContent = d || s;
}).observe(document.body,{attributes:true,attributeFilter:["data-status","data-detail"]});

// Poll for irohReady (set once the node joins the topic) to unlock the UI + show invite.
const readyTimer = setInterval(()=>{
  const r = globalThis.irohReady;
  if(!r) return;
  clearInterval(readyTimer);
  myId = r.id;
  $("id").textContent = short(r.id);
  $("tp").textContent = r.topic;
  $("in").disabled = false; $("send").disabled = false;
  $("in").placeholder = "type a message and press enter"; $("in").focus();

  // Build an invite URL that carries THIS node's id as ?peer= so new tabs
  // bootstrap the gossip overlay off us. Preserve relay + topic.
  const u = new URL(location.href);
  u.searchParams.set("peer", r.id);
  u.searchParams.set("topic", r.topic);
  u.searchParams.delete("name"); // let each joiner pick their own
  $("invurl").value = u.toString();
  $("inv").style.display = "block";
}, 150);

$("copy").onclick = ()=>{ $("invurl").select(); document.execCommand("copy"); $("copy").textContent="copied!"; setTimeout(()=>$("copy").textContent="copy",1200); };

$("f").addEventListener("submit",(e)=>{
  e.preventDefault();
  const v = $("in").value.trim();
  if(!v || typeof globalThis.irohSend!=="function") return;
  globalThis.irohSend(v);   // gossip broadcasts to NEIGHBORS, never echoes to the sender,
  addMsg("you", v, true);   // so render our own line locally instead of waiting for a callback.
  $("in").value=""; $("in").focus();
});

// Instantiate + run the wasm node.
const go = new Go();
WebAssembly.instantiateStreaming(fetch("/wasm-gossip-chat.wasm"), go.importObject)
  .then((r)=>go.run(r.instance))
  .catch((err)=>{ document.body.setAttribute("data-status","fail"); document.body.setAttribute("data-detail",String(err)); });
</script>
</body></html>`
