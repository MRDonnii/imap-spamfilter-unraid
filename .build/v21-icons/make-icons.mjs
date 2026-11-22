// Renders the PWA icons from the brand mark (gradient tile + shield glyph
// from filter/static/icons.svg #i-brand) with headless Chrome via raw CDP.
//   node .build/v21-icons/make-icons.mjs filter/static
// Output: icon-192.png, icon-512.png (rounded, transparent corners),
// icon-maskable-192.png, icon-maskable-512.png (full bleed, glyph inside the
// 80 % safe zone), apple-touch-icon.png (180, full bleed; iOS rounds it).
import { spawn } from "node:child_process";
import { writeFileSync, readFileSync } from "node:fs";

const out = process.argv[2] || "filter/static";
const sprite = readFileSync(`${out}/icons.svg`, "utf8");
const glyph = sprite.match(/<symbol id="i-brand" viewBox="0 0 24 24">([\s\S]*?)<\/symbol>/)[1];

function svg(size, { round, glyphScale }) {
  const r = round ? size * 0.225 : 0;
  const g = size * glyphScale;
  const off = (size - g) / 2;
  const sw = 1.9;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#8b5cf6"/><stop offset=".46" stop-color="#6366f1"/><stop offset="1" stop-color="#06b6d4"/>
    </linearGradient>
    <linearGradient id="sheen" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#fff" stop-opacity=".26"/><stop offset=".55" stop-color="#fff" stop-opacity="0"/>
    </linearGradient>
    <radialGradient id="glow" cx=".5" cy=".42" r=".5">
      <stop offset="0" stop-color="#fff" stop-opacity=".16"/><stop offset="1" stop-color="#fff" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="${size}" height="${size}" rx="${r}" fill="url(#bg)"/>
  <rect width="${size}" height="${size}" rx="${r}" fill="url(#glow)"/>
  <rect width="${size}" height="${size}" rx="${r}" fill="url(#sheen)"/>
  <g transform="translate(${off} ${off}) scale(${g / 24})" fill="none" stroke="#fff" stroke-width="${sw}"
     stroke-linecap="round" stroke-linejoin="round">${glyph}</g>
</svg>`;
}

const icons = [
  ["icon-192.png", 192, { round: true, glyphScale: 0.56 }],
  ["icon-512.png", 512, { round: true, glyphScale: 0.56 }],
  ["icon-maskable-192.png", 192, { round: false, glyphScale: 0.46 }],
  ["icon-maskable-512.png", 512, { round: false, glyphScale: 0.46 }],
  ["apple-touch-icon.png", 180, { round: false, glyphScale: 0.56 }],
];

const port = 9400 + Math.floor(Math.random() * 400);
const chrome = spawn("google-chrome", ["--headless=new", `--remote-debugging-port=${port}`, "--no-first-run",
  "--no-default-browser-check", "--disable-gpu", "--hide-scrollbars", `--user-data-dir=/tmp/sf-icons-${port}`,
  "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let target;
for (let i = 0; i < 60 && !target; i++) {
  await sleep(200);
  try { target = (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()).find((t) => t.type === "page"); } catch {}
}
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0; const waiters = new Map();
ws.onmessage = (m) => { const d = JSON.parse(m.data); if (d.id && waiters.has(d.id)) { waiters.get(d.id)(d); waiters.delete(d.id); } };
const send = (method, params = {}) => new Promise((r) => { const i = ++id; waiters.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
await send("Page.enable");
await send("Emulation.setDefaultBackgroundColorOverride", { color: { r: 0, g: 0, b: 0, a: 0 } });
for (const [name, size, opts] of icons) {
  await send("Emulation.setDeviceMetricsOverride", { width: size, height: size, deviceScaleFactor: 1, mobile: false });
  const html = `<!doctype html><html><head><style>html,body{margin:0;background:transparent}svg{display:block}</style></head><body>${svg(size, opts)}</body></html>`;
  await send("Page.navigate", { url: "data:text/html;base64," + Buffer.from(html).toString("base64") });
  await sleep(400);
  const shot = await send("Page.captureScreenshot", { format: "png", clip: { x: 0, y: 0, width: size, height: size, scale: 1 } });
  writeFileSync(`${out}/${name}`, Buffer.from(shot.result.data, "base64"));
  console.log("wrote", name);
}
ws.close(); chrome.kill(); process.exit(0);
