"use strict";

const byId = (id) => document.getElementById(id);
const homeView = byId("home-view");
const runView = byId("run-view");
const resultView = byId("result-view");
const logs = byId("logs");
const dnsDialog = byId("dns-dialog");
const runMode = byId("run-mode");
const automationOptions = byId("automation-options");
const autoDnsEnabled = byId("auto-dns-enabled");
const autoDnsFields = byId("auto-dns-fields");

let requestToken = "";
let family = "ipv4";
let useTls = false;
let currentResult = null;
let dnsPlanId = "";
let manualHome = false;
let lastStateKey = "";
let automationActive = false;

function show(view) {
  homeView.hidden = view !== "home";
  runView.hidden = view !== "run";
  resultView.hidden = view !== "result";
}

function toast(message, bad = false) {
  const box = byId("toast");
  box.textContent = message;
  box.className = bad ? "show bad" : "show";
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => { box.className = ""; }, 2600);
}

function setButtonLabel(id, text) {
  const button = byId(id);
  const label = button.querySelector("span");
  if (label) label.textContent = text;
  else button.textContent = text;
}

async function getJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || "HTTP " + response.status);
  return value;
}

async function postJson(path, body = {}) {
  const response = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-RR-Request-Token": requestToken,
    },
    body: JSON.stringify(body),
  });
  const value = await response.json();
  if (!response.ok || value.ok === false) {
    throw new Error(value.error || value.message || "HTTP " + response.status);
  }
  return value;
}

function bindSegments(groupId, onSelect) {
  const group = byId(groupId);
  group.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-value]");
    if (!button) return;
    group.querySelectorAll("button").forEach((item) => item.classList.toggle("selected", item === button));
    onSelect(button.dataset.value);
  });
}

function selectedIntervalHours() {
  if (runMode.value === "single") return null;
  const value = Number(runMode.value);
  return Number.isSafeInteger(value) && value > 0 ? value : null;
}

function updateRunMode() {
  const hours = selectedIntervalHours();
  automationOptions.hidden = hours === null;
  autoDnsFields.hidden = hours === null || !autoDnsEnabled.checked;
  setButtonLabel("start-button", hours === null ? "开始单次优选" : "开启自动测试");
  byId("run-mode-hint").textContent = hours === null
    ? "只运行一轮，完成后保留本轮最佳 IP。"
    : "第一轮立即运行；以后从上一轮结束后开始计时，每轮只保留 1 个 IP。";
  localStorage.setItem("rr-run-mode", runMode.value);
}

function formatNextRun(value) {
  if (!value) return "本轮运行中或正在安排下一轮";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "下次时间待定";
  return "下次 " + parsed.toLocaleString();
}

function renderAutomation(automation, running) {
  automationActive = automation && automation.enabled === true;
  const hours = Number(automation && automation.interval_hours);
  let text = "自动测试未开启";
  let paused = false;
  if (automationActive) {
    const interval = hours === 24 ? "全天模式（每 24 小时）" : "每 " + hours + " 小时";
    text = interval + " · 已启动 " + Number(automation.runs_started || 0) + " 轮 · " +
      (running ? "本轮运行中" : formatNextRun(automation.next_run_at));
    if (automation.dns_sync_enabled) {
      text += automation.dns_sync_paused ? " · DNS 自动解析已暂停" : " · 每轮自动解析 1 个 IP";
      paused = automation.dns_sync_paused === true;
    } else {
      text += " · DNS 由用户手动解析";
    }
  }
  [byId("home-automation-status"), byId("result-automation-status")].forEach((item) => {
    item.textContent = text;
    item.classList.toggle("active", automationActive && !paused);
    item.classList.toggle("paused", paused);
  });
  byId("result-automation-status").hidden = !automationActive;
  byId("home-stop-automation").hidden = !automationActive;
  byId("result-stop-automation").hidden = !automationActive;
  byId("start-button").disabled = automationActive;
  byId("update-button").disabled = automationActive;
  runMode.disabled = automationActive;
}

function renderResult(result) {
  currentResult = result;
  byId("result-ip").textContent = result.ip;
  byId("result-bandwidth").textContent = result.bandwidth + " Mbps";
  byId("result-real").textContent = result.realBandwidth + " Mbps";
  byId("result-speed").textContent = result.maxSpeed + " kB/s";
  byId("result-latency").textContent = result.latencyMs + " ms";
  byId("result-colo").textContent = result.dataCenter || "—";
  byId("result-elapsed").textContent = result.elapsed + " 秒";
}

function renderProgress(state) {
  const output = state.logs && state.logs.length ? state.logs.join("\n") : "";
  const progress = byId("stage-progress");
  const counter = byId("stage-counter");
  const badge = byId("status-badge");
  const badgeText = badge.querySelector("b");
  let value = 5;
  let label = "准备中";

  if (/更新.*IP 池|重新下载|正在准备 IP 池/.test((state.stage || "") + output)) {
    value = 35;
    label = "同步中";
  }
  if (/IP 池已就绪|正在从\s*\d+\s*个子网/.test(output)) {
    value = 16;
    label = "IP 池就绪";
  }
  const rtt = Array.from(output.matchAll(/RTT 测试进度:\s*(\d+)\/(\d+)/g)).at(-1);
  if (rtt) {
    const current = Number(rtt[1]);
    const total = Math.max(1, Number(rtt[2]));
    value = 20 + Math.round(Math.min(1, current / total) * 48);
    label = current + " / " + total;
  }
  if (/正在测试\s/.test(output)) {
    value = 76;
    label = "速度复测";
  }
  if (/峰值速度/.test(output)) {
    value = 88;
    label = "结果校验";
  }
  if (state.status === "completed") {
    value = 100;
    label = "100%";
  }
  if (state.status === "stopping") label = "停止中";
  if (state.status === "error") label = "未完成";

  progress.value = value;
  progress.textContent = value + "%";
  counter.textContent = label;
  badge.className = "status-badge " + (state.status === "error" ? "error" : state.status === "completed" ? "done" : "running");
  badgeText.textContent = state.status === "stopping" ? "停止中" : state.status === "error" ? "失败" : state.status === "completed" ? "已完成" : "优选中";
}

async function copyIp() {
  if (!currentResult) return;
  try {
    await navigator.clipboard.writeText(currentResult.ip);
    toast("IP 已复制");
  } catch (_error) {
    const input = document.createElement("textarea");
    input.value = currentResult.ip;
    document.body.appendChild(input);
    input.select();
    document.execCommand("copy");
    input.remove();
    toast("IP 已复制");
  }
}

function renderState(state) {
  const automation = state.automation || {};
  const running = state.status === "running" || state.status === "stopping";
  const key = [
    state.status,
    state.stage,
    state.error,
    state.result ? state.result.ip : "",
    automation.enabled,
    automation.next_run_at,
    automation.runs_started,
    automation.dns_sync_paused,
  ].join("|");
  renderAutomation(automation, running);
  [byId("home-automation-event"), byId("result-automation-event")].forEach((item) => {
    item.textContent = automationActive ? (state.detail || "") : "";
    item.hidden = !automationActive || !state.detail;
  });
  byId("stage").textContent = state.stage || "正在运行";
  byId("detail").textContent = state.detail || "";
  logs.textContent = state.logs && state.logs.length ? state.logs.join("\n") : "正在准备本轮任务…";
  logs.scrollTop = logs.scrollHeight;
  renderProgress(state);

  if (state.status === "running" || state.status === "stopping") {
    manualHome = false;
    show("run");
    byId("stop-button").disabled = state.status === "stopping";
    setButtonLabel("stop-button", state.status === "stopping" ? "正在停止…" : "停止本次任务");
  } else if (state.status === "completed" && state.result) {
    renderResult(state.result);
    if (!manualHome) show("result");
  } else if (state.status === "error") {
    if (key !== lastStateKey) toast(state.error || "任务失败", true);
    show("run");
    byId("detail").textContent = state.error || "";
    byId("stop-button").disabled = false;
    setButtonLabel("stop-button", automationActive ? "停止自动测试" : "返回首页");
  } else if (state.status === "cancelled") {
    if (key !== lastStateKey) toast("任务已停止");
    show("home");
  } else if (state.status === "completed" && !state.result) {
    if (key !== lastStateKey) toast(state.stage || "IP 池已更新");
    show("home");
  } else {
    show("home");
  }
  lastStateKey = key;
}

async function poll() {
  try {
    renderState(await getJson("/api/status"));
  } catch (error) {
    toast(error.message, true);
  } finally {
    window.setTimeout(poll, 600);
  }
}

async function startScan() {
  const bandwidth = Number(byId("bandwidth").value);
  if (!Number.isSafeInteger(bandwidth) || bandwidth <= 0) {
    toast("期望带宽必须是大于 0 的整数", true);
    return;
  }
  const intervalHours = selectedIntervalHours();
  let dnsSync = null;
  let dnsWriteConfirmed = false;
  if (intervalHours !== null && autoDnsEnabled.checked) {
    const zoneId = byId("auto-zone-id").value.trim();
    const recordName = byId("auto-record-name").value.trim();
    const apiToken = byId("auto-api-token").value;
    if (!zoneId || !recordName || !apiToken) {
      toast("自动解析需要填写 Zone ID、完整域名和 API Token", true);
      return;
    }
    const confirmed = window.confirm(
      "确认开启自动解析：每轮得到 1 个最佳 IP 后，自动创建或更新 " +
      recordName + " 的 A/AAAA 灰云记录。是否继续？"
    );
    if (!confirmed) return;
    dnsSync = { zone_id: zoneId, record_name: recordName, api_token: apiToken };
    dnsWriteConfirmed = true;
  }
  manualHome = false;
  currentResult = null;
  byId("metric-family").textContent = family.toUpperCase();
  byId("metric-port").textContent = useTls ? "TLS · 443" : "非 TLS · 80";
  byId("metric-bandwidth").textContent = bandwidth + " Mbps";
  try {
    if (intervalHours === null) {
      await postJson("/api/start", { family, use_tls: useTls, bandwidth });
    } else {
      await postJson("/api/automation/start", {
        family,
        use_tls: useTls,
        bandwidth,
        interval_hours: intervalHours,
        dns_sync: dnsSync,
        dns_write_confirmed: dnsWriteConfirmed,
      });
      if (dnsSync) {
        localStorage.setItem("rr-zone-id", dnsSync.zone_id);
        localStorage.setItem("rr-record-name", dnsSync.record_name);
      }
      byId("auto-api-token").value = "";
    }
    show("run");
  } catch (error) {
    toast(error.message, true);
  }
}

async function updateData() {
  manualHome = false;
  currentResult = null;
  try {
    await postJson("/api/update");
    show("run");
  } catch (error) {
    toast(error.message, true);
  }
}

async function stopTask() {
  if (!automationActive && byId("stop-button").textContent === "返回首页") {
    show("home");
    return;
  }
  try {
    await postJson("/api/stop");
  } catch (error) {
    toast(error.message, true);
  }
}

async function stopAutomation() {
  try {
    const value = await postJson("/api/stop");
    toast(value.message || "自动测试已停止");
    manualHome = true;
    show("home");
  } catch (error) {
    toast(error.message, true);
  }
}

function openDns() {
  if (!currentResult) return;
  dnsPlanId = "";
  byId("dns-ip").textContent = currentResult.ip;
  byId("zone-id").value = localStorage.getItem("rr-zone-id") || "";
  byId("record-name").value = localStorage.getItem("rr-record-name") || "";
  byId("api-token").value = "";
  byId("dns-preview").hidden = true;
  byId("preview-button").disabled = false;
  setButtonLabel("preview-button", "生成只读预览");
  dnsDialog.showModal();
}

function planText(plan) {
  const target = plan.record_type + " " + plan.record_name + " → " + plan.champion_ip;
  if (plan.action === "create") return "将创建 " + target + "（灰云，TTL 自动）。";
  if (plan.action === "update") {
    return "将把 " + plan.record_name + " 从 " + (plan.previous_content || "现有值") +
      " 更新为 " + plan.champion_ip + "（灰云，TTL 自动）。";
  }
  return target + " 已经一致，无需修改；确认后只会再次校验。";
}

async function previewDns() {
  const zoneId = byId("zone-id").value.trim();
  const recordName = byId("record-name").value.trim();
  const apiToken = byId("api-token").value;
  if (!zoneId || !recordName || !apiToken) {
    toast("请填写 Zone ID、完整域名和 API Token", true);
    return;
  }
  const button = byId("preview-button");
  button.disabled = true;
  setButtonLabel("preview-button", "正在读取记录…");
  byId("dns-preview").hidden = true;
  try {
    const value = await postJson("/api/dns/inspect", {
      zone_id: zoneId,
      record_name: recordName,
      api_token: apiToken,
    });
    dnsPlanId = value.plan.plan_id;
    byId("preview-text").textContent = planText(value.plan);
    byId("apply-button").textContent = value.plan.action === "unchanged" ? "确认并校验" : "确认写入 DNS";
    byId("dns-preview").hidden = false;
    byId("api-token").value = "";
    localStorage.setItem("rr-zone-id", value.plan.zone_id);
    localStorage.setItem("rr-record-name", value.plan.record_name);
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
    setButtonLabel("preview-button", "重新生成预览");
  }
}

async function applyDns() {
  if (!dnsPlanId) return;
  const button = byId("apply-button");
  button.disabled = true;
  button.textContent = "正在同步…";
  try {
    const value = await postJson("/api/dns/apply", { plan_id: dnsPlanId });
    const result = value.result;
    toast(result.record_type + " " + result.record_name + " 已同步为 " + result.content);
    dnsDialog.close();
  } catch (error) {
    dnsPlanId = "";
    byId("dns-preview").hidden = true;
    toast(error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "确认写入 DNS";
  }
}

async function init() {
  try {
    const config = await getJson("/api/config");
    requestToken = config.request_token;
    family = config.defaults.family;
    useTls = config.defaults.use_tls;
    byId("bandwidth").value = String(config.defaults.bandwidth);
    const allowedHours = new Set((config.automation && config.automation.interval_hours || []).map(String));
    const savedMode = localStorage.getItem("rr-run-mode") || "single";
    runMode.value = savedMode === "single" || allowedHours.has(savedMode) ? savedMode : "single";
    byId("auto-zone-id").value = localStorage.getItem("rr-zone-id") || "";
    byId("auto-record-name").value = localStorage.getItem("rr-record-name") || "";
    bindSegments("family-group", (value) => { family = value; });
    bindSegments("tls-group", (value) => { useTls = value === "true"; });
    runMode.addEventListener("change", updateRunMode);
    autoDnsEnabled.addEventListener("change", updateRunMode);
    byId("start-button").addEventListener("click", startScan);
    byId("update-button").addEventListener("click", updateData);
    byId("stop-button").addEventListener("click", stopTask);
    byId("copy-button").addEventListener("click", copyIp);
    byId("result-ip").addEventListener("click", copyIp);
    byId("dns-button").addEventListener("click", openDns);
    byId("home-stop-automation").addEventListener("click", stopAutomation);
    byId("result-stop-automation").addEventListener("click", stopAutomation);
    byId("home-button").addEventListener("click", () => { manualHome = true; show("home"); });
    byId("preview-button").addEventListener("click", previewDns);
    byId("apply-button").addEventListener("click", applyDns);
    dnsDialog.addEventListener("close", () => {
      byId("api-token").value = "";
      dnsPlanId = "";
      byId("dns-preview").hidden = true;
    });
    updateRunMode();
    poll();
  } catch (error) {
    toast("界面初始化失败：" + error.message, true);
  }
}

init();
