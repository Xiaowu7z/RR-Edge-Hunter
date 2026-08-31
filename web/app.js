"use strict";

const $ = (selector) => document.querySelector(selector);
const form = $("#optimizerForm");
const startButton = $("#startButton");
const stopButton = $("#stopButton");
const statusBadge = $("#statusBadge");
const stageName = $("#stageName");
const stageCounter = $("#stageCounter");
const stageProgress = $("#stageProgress");
const stageDetail = $("#stageDetail");
const logOutput = $("#logOutput");
const errorBox = $("#errorBox");
const resultSection = $("#resultSection");
const familyTabs = $("#familyTabs");
const winnerCard = $("#winnerCard");
const resultRows = $("#resultRows");
const toast = $("#toast");
const customSourcePanel = $("#customSourcePanel");
const ipInput = $("#ipInput");
const ipFile = $("#ipFile");
const ipSourceStatus = $("#ipSourceStatus");
const poolCount = $("#poolCount");
const targetHost = $("#targetHost");
const automationEnabled = $("#automationEnabled");
const automationInterval = $("#automationInterval");
const automationStatus = $("#automationStatus");
const automationForecast = $("#automationForecast");
const startButtonLabel = $("#startButtonLabel");

let requestToken = "";
let customIps = [];
let activeFamily = "";
let lastStatus = null;
let pollTimer = null;

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("show");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove("show"), 2600);
}

async function request(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-RR-Request-Token": requestToken },
    body: JSON.stringify(payload),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok || body.ok === false) throw new Error(body.message || body.error || `请求失败（${response.status}）`);
  return body;
}

function currentValue(name) {
  return form.querySelector(`input[name="${name}"]:checked`)?.value || "";
}

function setCustomStatus(message, kind = "") {
  ipSourceStatus.textContent = message;
  ipSourceStatus.className = `source-status ${kind}`.trim();
}

function sourceIsCustom() {
  return currentValue("ipSource") === "custom";
}

function updateSourcePanel() {
  customSourcePanel.hidden = !sourceIsCustom();
  if (!sourceIsCustom()) {
    customIps = [];
    setCustomStatus("使用测试主机当前 DNS 实际分配的 Cloudflare IP。", "ready");
  }
}

function selectedMode() {
  return currentValue("mode") || "balanced";
}

function updatePoolHint(config) {
  const mode = config.modes?.[selectedMode()];
  if (!mode) return;
  const cap = config.candidate_cap_per_family ? ` · 每族上限 ${config.candidate_cap_per_family}` : "";
  poolCount.textContent = `Micro ${mode.micro_candidates} · Full ${mode.final_candidates} × ${mode.full_rounds}${cap}`;
}

function estimateTrafficMb(modeName, family) {
  const mode = window.rrConfig?.modes?.[modeName];
  if (!mode) return null;
  const families = family === "dual" ? 2 : 1;
  const cap = Number(window.rrConfig?.candidate_cap_per_family || 128);
  return (cap * mode.pre_bytes + Math.min(cap, mode.micro_candidates) * mode.micro_bytes + Math.min(cap, mode.final_candidates) * mode.full_rounds * mode.full_bytes) * families / 1_000_000;
}

function formatDataAmountMb(value) {
  if (!Number.isFinite(value)) return "未知";
  if (value >= 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} TB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} GB`;
  return `${value.toFixed(1)} MB`;
}

function automationDailyUpperBoundMb(intervalMinutes, perRunMb) {
  if (!Number.isFinite(perRunMb)) return null;
  const minutes = Math.max(1, Number(intervalMinutes) || 1);
  // First run starts immediately; this is deliberately a conservative ceiling.
  return (Math.floor(24 * 60 / minutes) + 1) * perRunMb;
}

function updateAutomationChoice() {
  const enabled = automationEnabled.checked;
  startButtonLabel.textContent = enabled ? "开启定时自动优选" : "开始本机优选";
  const min = Number(window.rrConfig?.automation?.min_interval_minutes || 5);
  const max = Number(window.rrConfig?.automation?.max_interval_minutes || 1440);
  automationInterval.min = String(min);
  automationInterval.max = String(max);
  const interval = Number.parseInt(automationInterval.value, 10) || min;
  const perRunMb = estimateTrafficMb(currentValue("mode"), currentValue("family"));
  if (enabled) {
    const dailyMb = perRunMb === null ? null : automationDailyUpperBoundMb(interval, perRunMb);
    automationStatus.textContent = `首次立即运行；后续每 ${interval} 分钟重测一次。`;
    automationForecast.hidden = false;
    automationForecast.innerHTML = `<b>自动任务流量上限</b>：每轮约 ${formatDataAmountMb(perRunMb)}；按 ${interval} 分钟间隔计算，理论 24 小时上限约 ${formatDataAmountMb(dailyMb)}。实际因每轮耗时而更低。`;
  } else {
    automationStatus.textContent = "定时自动优选未开启";
    automationForecast.hidden = true;
    automationForecast.textContent = "";
  }
  automationStatus.classList.toggle("active", enabled);
}

function formatNextRun(value) {
  const next = new Date(value || "");
  return Number.isNaN(next.getTime()) ? "待安排" : next.toLocaleString();
}

function updateStatus(snapshot) {
  lastStatus = snapshot;
  const status = snapshot.status || "idle";
  statusBadge.className = `status-badge ${status}`;
  statusBadge.innerHTML = `<i></i><b>${escapeHtml({ idle: "待命", running: "运行中", stopping: "停止中", completed: "已完成", cancelled: "已停止", error: "出错" }[status] || status)}</b>`;
  stageName.textContent = snapshot.stage || "等待开始";
  const total = Number(snapshot.total || 0);
  const current = Number(snapshot.current || 0);
  stageCounter.textContent = total ? `${current} / ${total}` : "0 / 0";
  stageProgress.value = total ? Math.min(100, Math.round(current * 100 / total)) : 0;
  stageDetail.textContent = snapshot.detail || "";
  logOutput.textContent = (snapshot.logs || []).join("\n") || "等待测速任务…";
  logOutput.scrollTop = logOutput.scrollHeight;
  errorBox.hidden = !snapshot.error;
  errorBox.textContent = snapshot.error || "";
  const running = status === "running" || status === "stopping";
  const automation = snapshot.automation || {};
  const automated = automation.enabled === true;
  startButton.disabled = running || automated;
  stopButton.disabled = !(status === "running" || automated);
  if (automated) {
    automationEnabled.checked = true;
    automationInterval.value = String(automation.interval_minutes || automationInterval.value);
    const next = automation.next_run_at ? `下次：${formatNextRun(automation.next_run_at)}` : (running ? "本轮运行中" : "正在准备下一轮");
    automationStatus.textContent = `定时自动优选已开启 · 每 ${automation.interval_minutes} 分钟 · 已启动 ${automation.runs_started || 0} 轮 · ${next}`;
    automationStatus.classList.add("active");
    startButtonLabel.textContent = "定时自动优选运行中";
  } else if (!automationEnabled.checked) {
    automationStatus.textContent = "定时自动优选未开启";
    automationStatus.classList.remove("active");
    startButtonLabel.textContent = "开始本机优选";
  }
  if (snapshot.result) renderResult(snapshot.result);
}

function formatMbps(value) {
  return `${Number(value || 0).toFixed(1)} Mbps`;
}

function familyRows(result, familyName) {
  const family = result.families?.find((item) => item.family === familyName);
  if (!family) return [];
  return result.mode === "asia" ? (family.asia_ranked || []) : (family.ranked || []);
}

function renderResult(result) {
  const families = result.families || [];
  if (!families.length) return;
  resultSection.hidden = false;
  if (!families.some((item) => item.family === activeFamily)) activeFamily = families[0].family;
  familyTabs.innerHTML = "";
  for (const family of families) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = `${family.family} · ${family.candidate_count || 0}`;
    button.className = family.family === activeFamily ? "active" : "";
    button.addEventListener("click", () => { activeFamily = family.family; renderResult(result); });
    familyTabs.append(button);
  }
  const rows = familyRows(result, activeFamily);
  const winner = rows[0];
  if (!winner) {
    winnerCard.innerHTML = "<div class=\"winner-domain\"><small>NO RESULT</small><h3>没有可完成完整复核的 IP</h3><p>检查当前 DNS、协议栈和网络后重试。</p></div>";
    resultRows.innerHTML = "";
    return;
  }
  winnerCard.innerHTML = `
    <div class="winner-domain"><small>TOP 01 · ${escapeHtml(activeFamily)}</small><h3>${escapeHtml(winner.ip)}</h3><p>${escapeHtml(winner.pop || "POP 未知")} · ${escapeHtml(winner.stability || "待评估")} · ${Number(winner.rounds_tested || 0)} 轮完整复核</p></div>
    <div class="winner-stat"><small>复核底线</small><strong>${formatMbps(winner.round_floor_mbps)}</strong><em>任一失败即为 0</em></div>
    <div class="winner-stat"><small>平均速度</small><strong>${formatMbps(winner.avg_complete_mbps)}</strong><em>TTFB ${winner.median_ttfb_ms >= 0 ? `${Number(winner.median_ttfb_ms).toFixed(0)} ms` : "—"}</em></div>
    <div class="winner-stat"><small>成功率</small><strong>${Number(winner.success_rate_pct || 0).toFixed(1)}%</strong><em>波动 ${Number(winner.variation_pct || 0).toFixed(1)}%</em></div>`;
  resultRows.innerHTML = rows.map((row, index) => `
    <tr><td><div class="rank-domain"><span class="rank-number">${index + 1}</span><div><strong>${escapeHtml(row.ip)}</strong><small>${escapeHtml(row.family)} · ${Number(row.rounds_tested || 0)} 轮</small><div class="row-actions"><button class="copy-button" data-copy="${escapeHtml(row.ip)}">复制 IP</button></div></div></div></td>
    <td class="speed-cell"><strong>${formatMbps(row.round_floor_mbps)}</strong><small>最低轮次</small></td><td class="speed-cell"><strong>${formatMbps(row.avg_complete_mbps)}</strong><small>最高 ${formatMbps(row.max_complete_mbps)}</small></td>
    <td><span class="quality-pill">${Number(row.success_rate_pct || 0).toFixed(1)}%</span></td><td>${Number(row.variation_pct || 0).toFixed(1)}%</td><td><span class="pop-pill">${escapeHtml(row.pop || "UNKNOWN")}</span><br><small>${escapeHtml(row.loc || "")}</small></td><td class="address-cell">${escapeHtml((row.source_tags || []).join(" / ") || "当前 DNS")}</td></tr>`).join("");
  resultRows.querySelectorAll("[data-copy]").forEach((button) => button.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(button.dataset.copy || ""); showToast("已复制 IP"); } catch { showToast("复制失败，请手动复制"); }
  }));
}

async function poll() {
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    updateStatus(await response.json());
  } catch (error) {
    console.warn(error);
  }
}

function ensurePolling() {
  if (!pollTimer) pollTimer = window.setInterval(poll, 700);
}

async function applyParsed(result, sourceName) {
  customIps = result.ips || [];
  const warnings = (result.warnings || []).join(" · ");
  setCustomStatus(`${sourceName}：识别 ${customIps.length} 个公网 IP${warnings ? ` · ${warnings}` : ""}`, "ready");
  showToast(`已载入 ${customIps.length} 个 IP`);
}

$("#parseIpsButton").addEventListener("click", async () => {
  try { await applyParsed(await request("/api/ips/parse", { text: ipInput.value, filename: "paste.txt" }), "已识别粘贴内容"); } catch (error) { setCustomStatus(error.message, "error"); }
});

$("#chooseIpFile").addEventListener("click", () => ipFile.click());
ipFile.addEventListener("change", async () => {
  const file = ipFile.files?.[0];
  if (!file) return;
  const maxBytes = Number(window.rrConfig?.max_source_bytes || 1048576);
  if (file.size > maxBytes) {
    setCustomStatus(`文件不能超过 ${Math.round(maxBytes / 1024 / 1024)} MiB`, "error");
    ipFile.value = "";
    return;
  }
  try { await applyParsed(await request("/api/ips/parse", { text: await file.text(), filename: file.name }), `已导入 ${file.name}`); } catch (error) { setCustomStatus(error.message, "error"); }
  ipFile.value = "";
});

$("#fetchSubscriptionButton").addEventListener("click", async () => {
  const url = $("#subscriptionUrl").value.trim();
  try { const result = await request("/api/ips/fetch", { url }); await applyParsed(result, `已读取 ${result.final_url || "订阅"}`); } catch (error) { setCustomStatus(error.message, "error"); }
});

form.querySelectorAll("input[name=ipSource]").forEach((input) => input.addEventListener("change", updateSourcePanel));
form.querySelectorAll("input[name=mode]").forEach((input) => input.addEventListener("change", () => { updatePoolHint(window.rrConfig || {}); updateAutomationChoice(); }));
form.querySelectorAll("input[name=family]").forEach((input) => input.addEventListener("change", updateAutomationChoice));
automationEnabled.addEventListener("change", updateAutomationChoice);
automationInterval.addEventListener("change", () => {
  const min = Number(window.rrConfig?.automation?.min_interval_minutes || 5);
  const max = Number(window.rrConfig?.automation?.max_interval_minutes || 1440);
  const parsed = Number.parseInt(automationInterval.value, 10);
  automationInterval.value = String(Number.isFinite(parsed) ? Math.max(min, Math.min(max, parsed)) : min);
  localStorage.setItem("rr-edge-hunter-interval-minutes", automationInterval.value);
  updateAutomationChoice();
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (sourceIsCustom() && !customIps.length) { setCustomStatus("请先识别、导入或读取 IP 名单", "error"); return; }
  const payload = {
    mode: currentValue("mode"), family: currentValue("family"), operator: currentValue("operator"),
    target_host: targetHost.value.trim(), source: sourceIsCustom() ? "custom" : "dns", ips: customIps, confirmed: true,
  };
  const automated = automationEnabled.checked;
  if (automated) payload.interval_minutes = Number.parseInt(automationInterval.value, 10);
  const perRunMb = estimateTrafficMb(payload.mode, payload.family);
  const estimate = formatDataAmountMb(perRunMb);
  const confirmation = automated
    ? `将立即开始，并在每轮完成后等待 ${payload.interval_minutes} 分钟再重测。每轮最高计划流量约 ${estimate}；按此间隔的理论 24 小时上限约 ${formatDataAmountMb(automationDailyUpperBoundMb(payload.interval_minutes, perRunMb))}（实际因每轮耗时而更低）。是否开启？`
    : `本轮会进行真实 HTTPS 下载，最高计划流量约 ${estimate}。是否开始？`;
  if (!window.confirm(confirmation)) return;
  try {
    const result = await request(automated ? "/api/automation/start" : "/api/start", payload);
    showToast(result.message || (automated ? "定时自动优选已开启" : "优选已开始"));
    ensurePolling(); await poll();
  } catch (error) { showToast(error.message); }
});

stopButton.addEventListener("click", async () => {
  try {
    showToast((await request("/api/stop", {})).message);
    automationEnabled.checked = false;
    updateAutomationChoice();
  } catch (error) { showToast(error.message); }
});

(async () => {
  try {
    const config = await (await fetch("/api/config", { cache: "no-store" })).json();
    window.rrConfig = config; requestToken = config.request_token || "";
    targetHost.value = config.default_target_host || targetHost.value;
    const savedInterval = Number.parseInt(localStorage.getItem("rr-edge-hunter-interval-minutes") || "", 10);
    if (Number.isFinite(savedInterval)) automationInterval.value = String(savedInterval);
    $("#versionLabel").textContent = `Desktop ${config.version || ""}`;
    updatePoolHint(config); updateSourcePanel(); updateAutomationChoice(); ensurePolling(); await poll();
  } catch (error) { errorBox.hidden = false; errorBox.textContent = `初始化失败：${error.message}`; }
})();
