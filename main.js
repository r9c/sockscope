import { invoke } from "@tauri-apps/api/core";

const $ = (id) => document.getElementById(id);
const table = $("table");
const newList = $("newList");
const summary = $("summary");
const filter = $("filter");
const baselineBtn = $("baseline");
const rescanBtn = $("rescan");
const clearBaselineBtn = $("clearBaseline");
const onlyNewChk = $("onlyNew");
const onlyRiskyChk = $("onlyRisky");
const riskCountsEl = $("riskCounts");
const autoChk = $("autoRefresh");
const autoSel = $("autoInterval");

const KEY = "sockscope_baseline_v1";
const AUTO_ENABLED_KEY = "sockscope_auto_enabled";
const AUTO_SECS_KEY = "sockscope_auto_secs";

let baseline = [];
let lastData = { listeners: [] }; // cache
let autoTimer = null;
let isScanning = false; // prevent overlapping scans

try { baseline = JSON.parse(localStorage.getItem(KEY) || "[]"); } catch {}

const keyOf = (r) => `${r.process}|${r.exe}|${r.proto}|${r.port}`;

const riskLabel = (t) => ({
  "uncommon_port": "uncommon port",
  "ephemeral": "ephemeral",
  "suspicious_path": "suspicious path",
  "ww-exe": "world-writable exe",
})[t] || t;

function renderRiskBadges(risk) {
  const tags = (risk || "").split("+").filter(Boolean);
  if (!tags.length) return `<span class="risk-badge ok">ok</span>`;
  return tags.map(t => `<span class="risk-badge ${t}">${riskLabel(t)}</span>`).join(" ");
}

const escapeHtml = (s = "") =>
  s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
   .replace(/"/g,"&quot;").replace(/'/g,"&#39;");

function computeCounts(rows) {
  const counts = { ok:0, uncommon_port:0, ephemeral:0, suspicious_path:0, "ww-exe":0 };
  for (const r of rows) {
    const tags = (r.risk || "").split("+").filter(Boolean);
    if (!tags.length) counts.ok++;
    for (const t of tags) if (counts[t] !== undefined) counts[t]++;
  }
  return counts;
}

function render(data) {
  const baseSet = new Set(baseline.map(keyOf));
  const q = (filter?.value || "").trim().toLowerCase();

  let rows = data?.listeners ?? [];

  // local search
  if (q) {
    rows = rows.filter((r) =>
      (r.process || "").toLowerCase().includes(q) ||
      String(r.port ?? "").includes(q) ||
      (r.exe || "").toLowerCase().includes(q)
    );
  }

  // only NEW
  if (onlyNewChk?.checked && baseSet.size) {
    rows = rows.filter(r => !baseSet.has(keyOf(r)));
  }

  // only risky
  if (onlyRiskyChk?.checked) {
    rows = rows.filter(r => (r.risk || "") !== "");
  }

  let html = "";
  const newOnes = [];
  for (const r of rows) {
    const isNew = baseSet.size ? !baseSet.has(keyOf(r)) : false;
    if (isNew) newOnes.push(r);
    const exe = r.exe || "";
    html += `
      <div class="row" data-pid="${r.pid ?? ""}">
        <div>${escapeHtml(r.process || "?")}${isNew ? ' <span class="badge">NEW</span>' : ""}</div>
        <div>${r.pid ?? ""}</div>
        <div>${r.proto ?? ""}</div>
        <div>${r.port ?? ""}</div>
        <div class="cell-path" title="${escapeHtml(exe)}">
          ${escapeHtml(exe)}
          <button class="copy-btn" data-copy="${escapeHtml(exe)}">Copy</button>
        </div>
        <div class="actions">
          <button class="mini-btn end" data-end="${r.pid ?? ""}">End</button>
          ${renderRiskBadges(r.risk)}
        </div>
      </div>
    `;
  }
  table.innerHTML = html;

  summary.textContent = `${rows.length} listeners • ${newOnes.length} new`;
  newList.innerHTML = newOnes.map((r) =>
    `<li>${escapeHtml(r.process || "?")} : ${r.proto}/${r.port}</li>`
  ).join("");

  const counts = computeCounts(rows);
  riskCountsEl.innerHTML = `
    <div class="pill"><span>ok</span><span>${counts.ok}</span></div>
    <div class="pill"><span>uncommon</span><span>${counts.uncommon_port}</span></div>
    <div class="pill"><span>ephemeral</span><span>${counts.ephemeral}</span></div>
    <div class="pill"><span>suspicious</span><span>${counts.suspicious_path}</span></div>
    <div class="pill"><span>ww-exe</span><span>${counts["ww-exe"]}</span></div>
  `;
}

async function rescan() {
  if (isScanning) return; // skip if scan in progress
  isScanning = true;
  const old = summary.textContent;
  try {
    summary.textContent = "Invoking scan…";
    const json = await invoke("scan");
    lastData = JSON.parse(json) || { listeners: [] };
    render(lastData);
  } catch (e) {
    summary.textContent = "Scan failed";
    console.error(e);
    alert("Scan failed: " + e);
  } finally {
    isScanning = false;
    // restore summary if auto-refresh toggled
    if (autoChk?.checked) {
      summary.textContent = old.startsWith("Invoking") ? "Auto-refresh on" : "Auto-refresh on";
    }
  }
}

baselineBtn?.addEventListener("click", async () => {
  try {
    const json = await invoke("scan");
    const data = JSON.parse(json) || { listeners: [] };
    baseline = data.listeners || [];
    localStorage.setItem(KEY, JSON.stringify(baseline));
    alert("Baseline saved.");
    lastData = data;
    render(lastData);
  } catch (e) {
    alert("Could not save baseline: " + e);
  }
});

clearBaselineBtn?.addEventListener("click", () => {
  baseline = [];
  localStorage.removeItem(KEY);
  alert("Baseline cleared.");
  render(lastData);
});

table.addEventListener("click", async (e) => {
  const copyBtn = e.target.closest(".copy-btn");
  if (copyBtn) {
    try {
      await navigator.clipboard.writeText(copyBtn.dataset.copy || "");
      const old = summary.textContent;
      summary.textContent = "Path copied";
      setTimeout(() => (summary.textContent = old), 800);
    } catch { alert("Could not copy to clipboard"); }
    return;
  }

  const endBtn = e.target.closest(".mini-btn.end");
  if (endBtn) {
    const pid = Number(endBtn.dataset.end || "0");
    if (!pid) return;
    const confirmKill = confirm(`End process PID ${pid}? (SIGTERM)`);
    if (!confirmKill) return;
    try {
      await invoke("kill_pid", { pid });
      summary.textContent = `Sent TERM to ${pid}`;
      setTimeout(rescan, 500);
    } catch (err) {
      alert("End failed: " + err);
    }
  }
});

function debounce(fn, ms=100) {
  let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}
const refreshLocal = debounce(() => render(lastData), 80);
filter?.addEventListener("input", refreshLocal);
onlyNewChk?.addEventListener("change", () => render(lastData));
onlyRiskyChk?.addEventListener("change", () => render(lastData));

function clearAutoTimer() {
  if (autoTimer) { clearInterval(autoTimer); autoTimer = null; }
}
function startAutoTimer() {
  clearAutoTimer();
  const secs = Math.max(3, Number(autoSel?.value || "10"));
  autoTimer = setInterval(rescan, secs * 1000);
  localStorage.setItem(AUTO_SECS_KEY, String(secs));
  summary.textContent = "Auto-refresh on";
}

autoChk?.addEventListener("change", () => {
  const enabled = !!autoChk.checked;
  localStorage.setItem(AUTO_ENABLED_KEY, enabled ? "1" : "0");
  if (enabled) startAutoTimer(); else { clearAutoTimer(); summary.textContent = "Auto-refresh off"; }
});

autoSel?.addEventListener("change", () => {
  if (autoChk?.checked) startAutoTimer();
});

/* Restore auto settings */
(function restoreAuto() {
  const enabled = localStorage.getItem(AUTO_ENABLED_KEY) === "1";
  const secs = Number(localStorage.getItem(AUTO_SECS_KEY) || "10");
  if (autoSel) autoSel.value = String(secs || 10);
  if (autoChk) autoChk.checked = enabled;
  if (enabled) startAutoTimer();
})();

rescanBtn?.addEventListener("click", rescan);

rescan();
