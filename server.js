// server.js (HTTP-only; your Python TLS patch can upgrade to HTTPS)
// Fullscreen Three.js scene + WebSocket hub
// Streams: GPS + orientation + compass + local time
// Orientation is sent event-driven (max sensor rate), capped at ~1kHz if it ever exceeds.
// GPS/time are sent on a separate ticker (default 60Hz).
//
// Run:
//   npm install
//   node server.js
//
// Open:
//   http://<LAN_IP>:8080
//
// With your mkcert Python wrapper (TLS patch), this becomes HTTPS/WSS.

import http from "http";
import os from "os";
import { WebSocketServer } from "ws";

const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT || 8080);

function uid() {
  return Math.random().toString(16).slice(2) + "-" + Date.now().toString(16);
}

function getLocalIPv4s() {
  const nets = os.networkInterfaces();
  const out = [];
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === "IPv4" && !net.internal) out.push(net.address);
    }
  }
  return Array.from(new Set(out));
}

function json(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(obj));
}

function handler(req, res) {
  if (req.url === "/" || req.url === "/index.html") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(INDEX_HTML);
    return;
  }

  // Client uses this to show "Share on Wi-Fi" URLs.
  if (req.url === "/info") {
    const ips = getLocalIPv4s();
    const isTLS = !!req.socket.encrypted;
    const proto = isTLS ? "https" : "http";
    return json(res, 200, { proto, port: PORT, ips, host: HOST, use_https: isTLS });
  }

  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Not found");
}

const server = http.createServer(handler);
const wss = new WebSocketServer({ server });

// id -> { ws, state, lastSeen }
const peers = new Map();

function broadcast(obj, exceptWs = null) {
  const msg = JSON.stringify(obj);
  for (const { ws } of peers.values()) {
    if (ws === exceptWs) continue;
    if (ws.readyState !== ws.OPEN) continue;

    // Backpressure guard (prevents unbounded buffering if a client can't keep up)
    if (typeof ws.bufferedAmount === "number" && ws.bufferedAmount > 2_000_000) continue;

    ws.send(msg);
  }
}

function normalizeIncoming(next, msg) {
  // Compact schema:
  //   Orientation (high-rate): { t:"o", ts, q:[x,y,z,w], ch, ca, cs }
  //   State (lower-rate):      { t:"s", ts, lt, gps:[lat,lon,acc] }
  //
  // Back-compat:
  //   { type:"update", ts, timeISO, q:{}, gps:{}, compass:{} }

  if (msg && msg.t === "o") {
    if (Array.isArray(msg.q) && msg.q.length >= 4) {
      next.q = { x: +msg.q[0], y: +msg.q[1], z: +msg.q[2], w: +msg.q[3] };
    }
    if (typeof msg.ch === "number") {
      next.compass = {
        heading: +msg.ch,
        acc: (typeof msg.ca === "number") ? +msg.ca : null,
        src: (typeof msg.cs === "string") ? msg.cs : null,
      };
    } else if (msg.ch === null) {
      next.compass = null;
    }
    if (typeof msg.ts === "number") next.ts = msg.ts;
    return;
  }

  if (msg && msg.t === "s") {
    if (typeof msg.lt === "string") next.lt = msg.lt;
    if (Array.isArray(msg.gps) && msg.gps.length >= 3) {
      next.gps = { lat: +msg.gps[0], lon: +msg.gps[1], acc: +msg.gps[2] };
    } else if (msg.gps === null) {
      next.gps = null;
    }
    if (typeof msg.ts === "number") next.ts = msg.ts;
    return;
  }

  if (msg && msg.type === "update") {
    if (msg.q && typeof msg.q === "object") next.q = msg.q;
    if (msg.gps && typeof msg.gps === "object") next.gps = msg.gps;
    if (msg.compass && typeof msg.compass === "object") next.compass = msg.compass;
    if (typeof msg.timeISO === "string") next.timeISO = msg.timeISO;
    if (typeof msg.ts === "number") next.ts = msg.ts;
  }
}

wss.on("connection", (ws) => {
  const id = uid();

  const peer = {
    ws,
    state: { id },
    lastSeen: Date.now(),
  };
  peers.set(id, peer);

  // Send welcome + snapshot
  const snapshot = [];
  for (const [otherId, p] of peers.entries()) {
    if (otherId === id) continue;
    snapshot.push(p.state);
  }
  ws.send(JSON.stringify({ type: "welcome", id, peers: snapshot }));
  broadcast({ type: "join", peer: peer.state }, ws);

  ws.on("message", (data) => {
    let msg;
    try { msg = JSON.parse(String(data)); } catch { return; }
    if (!msg || typeof msg !== "object") return;

    const p = peers.get(id);
    if (!p) return;

    p.lastSeen = Date.now();

    const next = { ...p.state };
    normalizeIncoming(next, msg);
    p.state = next;

    broadcast({ type: "peer_update", peer: p.state }, ws);
  });

  ws.on("close", () => {
    peers.delete(id);
    broadcast({ type: "leave", id });
  });

  ws.on("error", () => {});
});

// Reap dead peers
setInterval(() => {
  const now = Date.now();
  for (const [id, p] of peers.entries()) {
    if (now - p.lastSeen > 60_000) {
      try { p.ws.close(); } catch {}
      peers.delete(id);
      broadcast({ type: "leave", id });
    }
  }
}, 15_000);

server.listen(PORT, HOST, () => {
  const ips = getLocalIPv4s();
  console.log(`Server running on http://${HOST}:${PORT}`);
  if (ips.length) {
    console.log("Open from another device on the same Wi-Fi:");
    for (const ip of ips) console.log(`  http://${ip}:${PORT}`);
  }
});

// ---------------------- Inlined client ----------------------
const INDEX_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover" />
  <title>Phone Twins</title>
  <style>
    :root{
      --bg:#000;
      --fg:#fff;
      --muted:rgba(255,255,255,.72);
      --muted2:rgba(255,255,255,.55);
      --panel:rgba(0,0,0,.62);
      --stroke:rgba(255,255,255,.12);
      --accent:#ffae00;
    }
    html, body {
      margin:0; height:100%; overflow:hidden;
      background:#000; color:var(--fg);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }
    #app { position:fixed; inset:0; }
    canvas { display:block; width:100%; height:100%; }

    /* Menu */
    #menu {
      position: fixed;
      top: max(env(safe-area-inset-top), 10px);
      left: max(env(safe-area-inset-left), 10px);
      width: min(420px, calc(100vw - 20px));
      pointer-events: auto;
      user-select: none;
      z-index: 10;
    }
    #menuInner {
      background: var(--panel);
      border: 1px solid var(--stroke);
      border-radius: 10px;
      backdrop-filter: blur(10px);
      padding: 10px;
    }
    #menuTop { display:flex; align-items:center; gap:8px; }
    #foldBtn {
      width: 34px; height: 34px;
      border-radius: 8px;
      border: 1px solid var(--stroke);
      background: rgba(255,255,255,.06);
      color: var(--fg);
      cursor: pointer;
      display:flex; align-items:center; justify-content:center;
      font-size: 16px; line-height: 1;
    }
    #toggleBtn {
      flex: 1;
      height: 34px;
      border-radius: 8px;
      border: 1px solid rgba(255,174,0,.45);
      background: rgba(255,174,0,.10);
      color: var(--fg);
      cursor: pointer;
      font-weight: 700;
      letter-spacing: .2px;
      display:flex; align-items:center; justify-content:center;
      gap:8px;
    }
    #dot {
      width: 8px; height: 8px;
      border-radius: 99px;
      background: rgba(255,255,255,.25);
      border: 1px solid rgba(255,255,255,.18);
    }
    #dot.on { background: var(--accent); border-color: rgba(255,174,0,.75); }
    #menuBody { margin-top: 10px; }
    #menu.collapsed #menuBody { display:none; }
    #menuTitle { margin: 6px 0 0 0; font-size: 11px; color: var(--muted2); }

    /* Modules */
    .module { margin-top: 10px; padding-top: 10px; border-top: 1px solid rgba(255,255,255,.10); }
    .moduleHeader{
      display:flex; align-items: baseline; justify-content: space-between;
      gap: 10px; margin-bottom: 8px;
    }
    .moduleHeader .name{ font-size: 12px; font-weight: 700; color: var(--fg); }
    .moduleHeader .sub{ font-size: 11px; color: var(--muted2); white-space: nowrap; }

    .pillWrap{ display:flex; flex-flow: row wrap; gap: 6px; }
    .pill{
      border-radius: 4px;
      border: 1px solid rgba(255,255,255,.12);
      background: rgba(255,255,255,.05);
      padding: 4px 6px;
      font-size: 11px;
      color: var(--fg);
      white-space: nowrap;
    }
    .pill.accent{ border-color: rgba(255,174,0,.55); background: rgba(255,174,0,.10); }
    .pill .k { color: var(--muted2); }
    .pill .v { color: var(--fg); }

    /* 3D labels */
    .label {
      position: fixed;
      transform: translate(-50%, -120%);
      pointer-events: none;
      padding: 6px 8px;
      border-radius: 8px;
      background: rgba(0,0,0,0.55);
      border: 1px solid rgba(255,255,255,0.12);
      font-size: 11px;
      line-height: 1.2;
      white-space: nowrap;
      color: #fff;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }
    .label b { color: var(--accent); font-weight: 800; }

    /* share links */
    #shareLinks { margin-top: 8px; font-size: 11px; color: var(--muted2); }
    #shareLinks a { color: var(--accent); text-decoration: none; }
    #shareLinks a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div id="app"></div>

  <div id="menu" class="collapsed">
    <div id="menuInner">
      <div id="menuTop">
        <button id="foldBtn" title="Expand / collapse">☰</button>
        <button id="toggleBtn">
          <span id="dot"></span>
          <span id="toggleText">Start streaming</span>
        </button>
      </div>
      <div id="menuTitle">WebSockets • Three.js • GPS • Orientation • Compass • Local time</div>

      <div id="menuBody">
        <div id="shareLinks"></div>

        <div id="modules">
          <div id="peersModule" class="module">
            <div class="moduleHeader">
              <div class="name">Peers</div>
              <div class="sub" id="peerCount">0</div>
            </div>
            <div id="peerCards"></div>
          </div>

          <div id="selfModule" class="module">
            <div class="moduleHeader">
              <div class="name">You</div>
              <div class="sub" id="selfId">—</div>
            </div>
            <div class="pillWrap" id="selfPills"></div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script type="module">
    import * as THREE from "https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.module.js";

    const WS_URL = (new URLSearchParams(location.search).get("ws"))
      || ((location.protocol === "https:" ? "wss://" : "ws://") + location.host);

    // --- High-rate knobs (best-effort) ---
    const ORI_TARGET_HZ = 1000;              // ceiling; actual is sensor-limited
    const ORI_MIN_DT_MS = 1000 / ORI_TARGET_HZ;
    const STATE_HZ = 60;                     // GPS/local-time cadence
    const STATE_DT_MS = 1000 / STATE_HZ;
    const WS_BACKPRESSURE_BYTES = 2_000_000; // stop sending if too buffered

    // UI refs
    const menu = document.getElementById("menu");
    const foldBtn = document.getElementById("foldBtn");
    const toggleBtn = document.getElementById("toggleBtn");
    const toggleText = document.getElementById("toggleText");
    const dot = document.getElementById("dot");
    const shareLinks = document.getElementById("shareLinks");
    const peerCountEl = document.getElementById("peerCount");
    const peerCards = document.getElementById("peerCards");
    const selfIdEl = document.getElementById("selfId");
    const selfPills = document.getElementById("selfPills");

    foldBtn.addEventListener("click", () => menu.classList.toggle("collapsed"));

    async function populateShareLinks(){
      try{
        const res = await fetch("/info", { cache: "no-store" });
        const info = await res.json();
        const { proto, port, ips } = info || {};
        if (!ips || ips.length === 0) { shareLinks.innerHTML = ""; return; }
        const links = ips.map(ip => \`\${proto}://\${ip}:\${port}\`).slice(0, 6);
        shareLinks.innerHTML =
          \`<div style="margin-top:10px"><b style="color:var(--accent)">Share on Wi-Fi</b></div>\` +
          links.map(u => \`<div><a href="\${u}" target="_blank" rel="noopener">\${u}</a></div>\`).join("");
      } catch {
        shareLinks.innerHTML = "";
      }
    }
    populateShareLinks();

    // State
    let myId = null;
    let ws = null;
    let streaming = false;

    let geoWatchId = null;
    let stateTimer = null;
    let lastOriSendPerf = 0;

    let orientationListening = false;
    let absSensor = null; // Optional Generic Sensor API
    let usingAbsSensor = false;

    // UI should NOT rebuild on sensor-rate updates
    let modulesDirty = true;

    const localState = {
      q: { x: 0, y: 0, z: 0, w: 1 },
      gps: null,           // {lat,lon,acc}
      compass: null,       // {heading, acc?, src?}
      ts: Date.now(),      // epoch ms
      lt: new Date().toLocaleTimeString(), // sender-local time string
    };

    const peers = new Map(); // id -> { state, group, labelEl }

    // Three.js scene
    const container = document.getElementById("app");
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x000000, 7, 22);

    const camera = new THREE.PerspectiveCamera(65, window.innerWidth / window.innerHeight, 0.05, 100);
    camera.position.set(0, 3.5, 7.5);
    camera.lookAt(0, 1.2, 0);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
    renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
    renderer.setSize(window.innerWidth, window.innerHeight);
    container.appendChild(renderer.domElement);

    scene.add(new THREE.AmbientLight(0xffffff, 0.55));
    const dir = new THREE.DirectionalLight(0xffffff, 0.9);
    dir.position.set(5, 8, 5);
    scene.add(dir);

    const ground = new THREE.Mesh(
      new THREE.CircleGeometry(20, 64),
      new THREE.MeshStandardMaterial({ color: 0x050505, roughness: 1, metalness: 0 })
    );
    ground.rotation.x = -Math.PI / 2;
    ground.position.y = 0;
    scene.add(ground);

    const grid = new THREE.GridHelper(20, 20, 0x333333, 0x111111);
    grid.position.y = 0.01;
    scene.add(grid);

    // Local phone twin
    const localGroup = new THREE.Group();
    localGroup.position.set(0, 1.0, 0);
    scene.add(localGroup);

    const phoneGeom = new THREE.BoxGeometry(0.6, 1.2, 0.08);
    const localMat = new THREE.MeshStandardMaterial({ color: 0xffae00, roughness: 0.45, metalness: 0.08 });
    localGroup.add(new THREE.Mesh(phoneGeom, localMat));
    localGroup.add(new THREE.ArrowHelper(new THREE.Vector3(0, 0, -1), new THREE.Vector3(0,0,0), 1.0, 0xffffff));

    // 3D labels (DOM overlay)
    const labels = []; // { id, el, object3D }
    function makeLabelEl(html) {
      const el = document.createElement("div");
      el.className = "label";
      el.innerHTML = html;
      document.body.appendChild(el);
      return el;
    }
    function registerLabel(id, object3D, initialHtml) {
      const el = makeLabelEl(initialHtml);
      labels.push({ id, el, object3D });
      return el;
    }
    function updateLabels() {
      const v = new THREE.Vector3();
      for (const item of labels) {
        v.setFromMatrixPosition(item.object3D.matrixWorld);
        v.project(camera);
        const visible = v.z < 1 && v.z > -1 && Math.abs(v.x) <= 1.2 && Math.abs(v.y) <= 1.2;
        item.el.style.display = visible ? "block" : "none";
        if (!visible) continue;
        const x = (v.x * 0.5 + 0.5) * window.innerWidth;
        const y = (-v.y * 0.5 + 0.5) * window.innerHeight;
        item.el.style.left = \`\${x}px\`;
        item.el.style.top  = \`\${y}px\`;
      }
    }

    // Deterministic peer placement
    function hashTo01(str) {
      let h = 2166136261;
      for (let i = 0; i < str.length; i++) {
        h ^= str.charCodeAt(i);
        h = Math.imul(h, 16777619);
      }
      return (h >>> 0) / 4294967295;
    }
    function peerPosition(id) {
      const t = hashTo01(id);
      const angle = t * Math.PI * 2;
      const radius = 4.0;
      return new THREE.Vector3(Math.cos(angle) * radius, 1.0, Math.sin(angle) * radius);
    }
    function peerColor(id) {
      const t = hashTo01(id);
      return new THREE.Color().setHSL(t, 0.65, 0.55);
    }

    function ensurePeer(id, state = {}) {
      if (id === myId) return;
      if (peers.has(id)) return;

      const group = new THREE.Group();
      group.position.copy(peerPosition(id));
      scene.add(group);

      const mat = new THREE.MeshStandardMaterial({ color: peerColor(id), roughness: 0.5, metalness: 0.06 });
      group.add(new THREE.Mesh(phoneGeom, mat));
      group.add(new THREE.ArrowHelper(new THREE.Vector3(0, 0, -1), new THREE.Vector3(0,0,0), 1.0, 0xffffff));

      const base = new THREE.Mesh(
        new THREE.CylinderGeometry(0.25, 0.25, 0.05, 24),
        new THREE.MeshStandardMaterial({ color: 0x0b0b0b, roughness: 1, metalness: 0 })
      );
      base.position.y = -0.8;
      group.add(base);

      const labelEl = registerLabel(id, group, \`<b>\${id.slice(0,8)}…</b>\`);
      peers.set(id, { state, group, labelEl });

      modulesDirty = true;
    }

    function removePeer(id) {
      const p = peers.get(id);
      if (!p) return;
      scene.remove(p.group);
      for (let i = labels.length - 1; i >= 0; i--) {
        if (labels[i].id === id) {
          labels[i].el.remove();
          labels.splice(i, 1);
        }
      }
      peers.delete(id);
      modulesDirty = true;
    }

    function applyPeerState(id, state) {
      ensurePeer(id, state);
      const p = peers.get(id);
      if (!p) return;

      p.state = { ...p.state, ...state };

      const q = p.state.q;
      if (q && typeof q === "object") {
        p.group.quaternion.set(+q.x, +q.y, +q.z, +q.w);
      }

      modulesDirty = true;
    }

    // Orientation helpers
    const zee = new THREE.Vector3(0, 0, 1);
    const euler = new THREE.Euler();
    const q0 = new THREE.Quaternion();
    const q1 = new THREE.Quaternion(-Math.sqrt(0.5), 0, 0, Math.sqrt(0.5));

    function screenOrientationRad() {
      const a = (screen.orientation && typeof screen.orientation.angle === "number")
        ? screen.orientation.angle
        : (typeof window.orientation === "number" ? window.orientation : 0);
      return a * Math.PI / 180;
    }

    function deviceEulerToQuaternion(alpha, beta, gamma, orientRad) {
      const degtorad = Math.PI / 180;
      euler.set(beta * degtorad, alpha * degtorad, -gamma * degtorad, "YXZ");
      const q = new THREE.Quaternion().setFromEuler(euler);
      q.multiply(q1);
      q.multiply(q0.setFromAxisAngle(zee, -orientRad));
      return q;
    }

    function computeCompassHeadingDeg(alpha, beta, gamma, orientRad) {
      const degtorad = Math.PI / 180;
      const _x = (beta  || 0) * degtorad;
      const _y = (gamma || 0) * degtorad;
      const _z = (alpha || 0) * degtorad;

      const cX = Math.cos(_x), cY = Math.cos(_y), cZ = Math.cos(_z);
      const sX = Math.sin(_x), sY = Math.sin(_y), sZ = Math.sin(_z);

      const Vx = -cZ * sY - sZ * sX * cY;
      const Vy = -sZ * sY + cZ * sX * cY;

      let heading = Math.atan2(Vx, Vy) * 180 / Math.PI;
      heading = (heading + 360) % 360;

      const orientDeg = (orientRad || 0) * 180 / Math.PI;
      heading = (heading + orientDeg + 360) % 360;

      return heading;
    }

    // WebSocket send (max-rate)
    function wsCanSend() {
      return ws && ws.readyState === WebSocket.OPEN && (ws.bufferedAmount || 0) < WS_BACKPRESSURE_BYTES;
    }

    function sendOrientationFast(nowPerf) {
      if (!wsCanSend()) return;

      // cap to ~1kHz if events exceed
      if (nowPerf - lastOriSendPerf < ORI_MIN_DT_MS) return;
      lastOriSendPerf = nowPerf;

      const ts = Date.now();
      localState.ts = ts;

      const q = localState.q;
      const comp = localState.compass;

      ws.send(JSON.stringify({
        t: "o",
        ts,
        q: [q.x, q.y, q.z, q.w],
        ch: (comp && typeof comp.heading === "number") ? comp.heading : null,
        ca: (comp && typeof comp.acc === "number") ? comp.acc : null,
        cs: (comp && typeof comp.src === "string") ? comp.src : null,
      }));
    }

    // If Generic Sensor API is available, use it for quaternion at best effort frequency.
    function startAbsSensorQuaternion() {
      if (!("AbsoluteOrientationSensor" in window)) return false;
      try {
        // Some browsers require secure context + permissions.
        absSensor = new AbsoluteOrientationSensor({ frequency: ORI_TARGET_HZ, referenceFrame: "device" });
        usingAbsSensor = true;

        absSensor.addEventListener("reading", () => {
          const qq = absSensor.quaternion;
          if (!qq) return;
          localState.q = { x: qq[0], y: qq[1], z: qq[2], w: qq[3] };
          localGroup.quaternion.set(qq[0], qq[1], qq[2], qq[3]);
          sendOrientationFast(performance.now());
        });

        absSensor.addEventListener("error", () => {
          // fall back
          usingAbsSensor = false;
          try { absSensor.stop(); } catch {}
          absSensor = null;
        });

        absSensor.start();
        return true;
      } catch {
        usingAbsSensor = false;
        absSensor = null;
        return false;
      }
    }

    function stopAbsSensorQuaternion() {
      if (absSensor) {
        try { absSensor.stop(); } catch {}
      }
      absSensor = null;
      usingAbsSensor = false;
    }

    // deviceorientation handler (full) OR (compass-only if usingAbsSensor)
    function onDeviceOrientation(ev) {
      if (ev.alpha == null || ev.beta == null || ev.gamma == null) return;
      const orientRad = screenOrientationRad();

      // Compass
      if (typeof ev.webkitCompassHeading === "number") {
        localState.compass = {
          heading: (ev.webkitCompassHeading + 360) % 360,
          acc: (typeof ev.webkitCompassAccuracy === "number") ? ev.webkitCompassAccuracy : null,
          src: "webkit",
        };
      } else {
        const h = computeCompassHeadingDeg(ev.alpha, ev.beta, ev.gamma, orientRad);
        localState.compass = { heading: h, acc: null, src: ev.absolute ? "abs" : "rel" };
      }

      if (usingAbsSensor) {
        // Quaternion comes from sensor; don't send twice
        return;
      }

      // Quaternion for 3D twin
      const q = deviceEulerToQuaternion(ev.alpha, ev.beta, ev.gamma, orientRad);
      localState.q = { x: q.x, y: q.y, z: q.z, w: q.w };
      localGroup.quaternion.set(q.x, q.y, q.z, q.w);

      // Send at sensor rate (capped)
      sendOrientationFast(performance.now());
    }

    // Desktop fallback: drag to rotate local phone (also sends if streaming)
    let dragging = false;
    let lastX = 0, lastY = 0;
    renderer.domElement.addEventListener("pointerdown", (e) => { dragging = true; lastX = e.clientX; lastY = e.clientY; });
    window.addEventListener("pointerup", () => dragging = false);
    window.addEventListener("pointermove", (e) => {
      if (!dragging) return;
      const dx = (e.clientX - lastX) / window.innerWidth;
      const dy = (e.clientY - lastY) / window.innerHeight;
      lastX = e.clientX; lastY = e.clientY;

      const yaw = -dx * Math.PI * 1.6;
      const pitch = -dy * Math.PI * 1.2;

      const qYaw = new THREE.Quaternion().setFromAxisAngle(new THREE.Vector3(0,1,0), yaw);
      const qPitch = new THREE.Quaternion().setFromAxisAngle(new THREE.Vector3(1,0,0), pitch);
      localGroup.quaternion.multiply(qYaw).multiply(qPitch);

      const q = localGroup.quaternion;
      localState.q = { x: q.x, y: q.y, z: q.z, w: q.w };

      if (streaming) sendOrientationFast(performance.now());
    });

    // GPS
    function startGeolocation() {
      if (!("geolocation" in navigator)) throw new Error("Geolocation not supported");
      geoWatchId = navigator.geolocation.watchPosition(
        (pos) => {
          const c = pos.coords;
          localState.gps = { lat: c.latitude, lon: c.longitude, acc: c.accuracy ?? 0 };
          modulesDirty = true;
        },
        () => {},
        { enableHighAccuracy: true, maximumAge: 250, timeout: 15000 }
      );
    }

    function stopGeolocation() {
      if (geoWatchId != null && navigator.geolocation?.clearWatch) {
        navigator.geolocation.clearWatch(geoWatchId);
      }
      geoWatchId = null;
      localState.gps = null;
      modulesDirty = true;
    }

    // Lower-rate "state" ticker (GPS + sender-local time)
    function startStateTicker() {
      let last = performance.now();
      stateTimer = setInterval(() => {
        localState.lt = new Date().toLocaleTimeString();

        if (!wsCanSend()) return;
        const now = performance.now();
        if (now - last < STATE_DT_MS * 0.75) return;
        last = now;

        const ts = Date.now();
        localState.ts = ts;

        const g = localState.gps;
        ws.send(JSON.stringify({
          t: "s",
          ts,
          lt: localState.lt,
          gps: g ? [g.lat, g.lon, g.acc] : null
        }));

        modulesDirty = true;
      }, Math.max(1, Math.floor(STATE_DT_MS / 2)));
    }

    function stopStateTicker() {
      if (stateTimer) clearInterval(stateTimer);
      stateTimer = null;
    }

    // WebSocket
    function connectWS() {
      return new Promise((resolve, reject) => {
        ws = new WebSocket(WS_URL);

        ws.addEventListener("open", () => resolve());

        ws.addEventListener("message", (ev) => {
          let msg;
          try { msg = JSON.parse(ev.data); } catch { return; }

          if (msg.type === "welcome") {
            myId = msg.id;
            selfIdEl.textContent = myId ? (myId.slice(0,8) + "…") : "—";
            for (const st of (msg.peers || [])) if (st?.id) applyPeerState(st.id, st);
            modulesDirty = true;
          }

          if (msg.type === "join" && msg.peer?.id) {
            applyPeerState(msg.peer.id, msg.peer);
            modulesDirty = true;
          }

          if (msg.type === "leave" && msg.id) {
            removePeer(msg.id);
            modulesDirty = true;
          }

          if (msg.type === "peer_update" && msg.peer?.id) {
            applyPeerState(msg.peer.id, msg.peer);
          }
        });

        ws.addEventListener("error", () => reject(new Error("WebSocket error")));
      });
    }

    // Permissions
    async function requestMotionPermissionIfNeeded() {
      if (typeof DeviceOrientationEvent !== "undefined" && typeof DeviceOrientationEvent.requestPermission === "function") {
        const res = await DeviceOrientationEvent.requestPermission();
        if (res !== "granted") throw new Error("Motion permission denied");
      }
    }

    function startOrientation() {
      if (orientationListening) return;
      orientationListening = true;

      // Try Generic Sensor API for faster quaternion (Android/Chrome, etc.)
      const startedSensor = startAbsSensorQuaternion();

      // Always attach deviceorientation for compass (and quaternion fallback if sensor not used)
      window.addEventListener("deviceorientation", onDeviceOrientation, true);
      window.addEventListener("deviceorientationabsolute", onDeviceOrientation, true);

      // If sensor didn't start, fallback runs via deviceorientation handler (which sends)
      usingAbsSensor = startedSensor;
    }

    function stopOrientation() {
      if (!orientationListening) return;
      orientationListening = false;

      window.removeEventListener("deviceorientation", onDeviceOrientation, true);
      window.removeEventListener("deviceorientationabsolute", onDeviceOrientation, true);

      stopAbsSensorQuaternion();
    }

    function setStreamingUI(on) {
      streaming = on;
      dot.classList.toggle("on", on);
      toggleText.textContent = on ? "Stop streaming" : "Start streaming";
      toggleBtn.style.borderColor = on ? "rgba(255,174,0,.75)" : "rgba(255,174,0,.45)";
      toggleBtn.style.background = on ? "rgba(255,174,0,.16)" : "rgba(255,174,0,.10)";
      modulesDirty = true;
    }

    async function startStreaming() {
      await requestMotionPermissionIfNeeded();
      await connectWS();

      if (!labels.find(x => x.id === "me")) {
        registerLabel("me", localGroup, "<b>you</b>");
      }

      startOrientation();
      startGeolocation();
      startStateTicker();

      setStreamingUI(true);
    }

    async function stopStreaming() {
      stopStateTicker();
      stopGeolocation();
      stopOrientation();

      try { if (ws && ws.readyState === WebSocket.OPEN) ws.close(); } catch {}
      ws = null;

      setStreamingUI(false);
    }

    toggleBtn.addEventListener("click", async () => {
      try {
        if (!streaming) await startStreaming();
        else await stopStreaming();
      } catch (e) {
        console.error(e);
        setStreamingUI(false);
      }
    });

    // Pills
    function pill(k, v, accent=false) {
      const el = document.createElement("div");
      el.className = "pill" + (accent ? " accent" : "");
      el.innerHTML = \`<span class="k">\${k}:</span> <span class="v">\${v}</span>\`;
      return el;
    }

    function fmtGps(gps) {
      if (!gps) return "—";
      const lat = Number(gps.lat).toFixed(5);
      const lon = Number(gps.lon).toFixed(5);
      const acc = Math.round(Number(gps.acc ?? 0));
      return \`\${lat},\${lon} ±\${acc}m\`;
    }

    function fmtCompass(comp) {
      if (!comp || typeof comp.heading !== "number" || Number.isNaN(comp.heading)) return "—";
      const h = Math.round(comp.heading);
      const a = (typeof comp.acc === "number" && !Number.isNaN(comp.acc)) ? \` ±\${Math.round(comp.acc)}°\` : "";
      return \`\${h}°\${a}\`;
    }

    function quatToEulerDeg(q) {
      if (!q) return null;
      const quat = new THREE.Quaternion(q.x, q.y, q.z, q.w);
      const e = new THREE.Euler().setFromQuaternion(quat, "YXZ");
      const d = (r) => Math.round((r * 180 / Math.PI) * 10) / 10;
      return \`x\${d(e.x)} y\${d(e.y)} z\${d(e.z)}\`;
    }

    function renderPeerCard(id, st) {
      const card = document.createElement("div");
      card.className = "module";

      const head = document.createElement("div");
      head.className = "moduleHeader";

      const left = document.createElement("div");
      left.className = "name";
      left.textContent = id.slice(0,8) + "…";

      const right = document.createElement("div");
      right.className = "sub";
      const age = (typeof st?.ts === "number") ? (Date.now() - st.ts) : null;
      right.textContent = age == null ? "" : \`\${Math.max(0, Math.round(age/1000))}s\`;

      head.appendChild(left);
      head.appendChild(right);

      const wrap = document.createElement("div");
      wrap.className = "pillWrap";

      const t = (typeof st?.lt === "string") ? st.lt : "—";
      wrap.appendChild(pill("time", t, true));
      wrap.appendChild(pill("gps", fmtGps(st?.gps)));
      wrap.appendChild(pill("compass", fmtCompass(st?.compass), true));
      const eul = quatToEulerDeg(st?.q);
      wrap.appendChild(pill("ori", eul ?? "—"));
      if (st?.q) {
        const qv = \`\${st.q.x.toFixed(2)},\${st.q.y.toFixed(2)},\${st.q.z.toFixed(2)},\${st.q.w.toFixed(2)}\`;
        wrap.appendChild(pill("q", qv));
      } else {
        wrap.appendChild(pill("q", "—"));
      }

      card.appendChild(head);
      card.appendChild(wrap);

      // Update existing 3D label content without recreating nodes
      const p = peers.get(id);
      if (p?.labelEl) {
        const comp = (st?.compass && typeof st.compass.heading === "number") ? \` \${Math.round(st.compass.heading)}°\` : "";
        p.labelEl.innerHTML = \`<b>\${id.slice(0,8)}…</b>\${comp}\`;
      }

      return card;
    }

    function renderSelfPills() {
      selfPills.innerHTML = "";
      localState.lt = new Date().toLocaleTimeString();

      selfPills.appendChild(pill("stream", streaming ? "on" : "off", true));
      selfPills.appendChild(pill("ws", (ws && ws.readyState === WebSocket.OPEN) ? "up" : "down"));
      selfPills.appendChild(pill("time", localState.lt, true));
      selfPills.appendChild(pill("gps", fmtGps(localState.gps)));
      selfPills.appendChild(pill("compass", fmtCompass(localState.compass), true));
      const eul = quatToEulerDeg(localState.q);
      selfPills.appendChild(pill("ori", eul ?? "—"));
      const q = localState.q ? \`\${localState.q.x.toFixed(2)},\${localState.q.y.toFixed(2)},\${localState.q.z.toFixed(2)},\${localState.q.w.toFixed(2)}\` : "—";
      selfPills.appendChild(pill("q", q));
    }

    function renderModules() {
      peerCards.innerHTML = "";
      const ids = [...peers.keys()];
      peerCountEl.textContent = String(ids.length);
      for (const id of ids) {
        const st = peers.get(id)?.state || {};
        peerCards.appendChild(renderPeerCard(id, st));
      }
      renderSelfPills();
    }

    // UI refresh loop (keeps DOM work bounded even if network/sensors are high-rate)
    setInterval(() => {
      if (modulesDirty) {
        modulesDirty = false;
        renderModules();
      } else {
        renderSelfPills();
      }
    }, 50); // 20Hz UI updates (fast but safe)

    // Animate
    function animate() {
      requestAnimationFrame(animate);
      localGroup.position.y = 1.0 + Math.sin(Date.now() * 0.0012) * 0.02;
      updateLabels();
      renderer.render(scene, camera);
    }
    animate();

    window.addEventListener("resize", () => {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    });

    // Init
    setStreamingUI(false);
    modulesDirty = true;
  </script>
</body>
</html>`;
