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
const resultKicker = $("#resultKicker");
const resultTitle = $("#resultTitle");
const resultDescription = $("#resultDescription");
const toast = $("#toast");
const customSourcePanel = $("#customSourcePanel");
const ipInput = $("#ipInput");
const ipFile = $("#ipFile");
const ipSourceStatus = $("#ipSourceStatus");
const poolCount = $("#poolCount");
const targetHost = $("#targetHost");
const argoValidationEnabled = $("#argoValidationEnabled");
const argoValidationPanel = $("#argoValidationPanel");
const nodePort = $("#nodePort");
const wsPath = $("#wsPath");
const targetMbps = $("#targetMbps");
const automationEnabled = $("#automationEnabled");
const automationInterval = $("#automationInterval");
const automationStatus = $("#automationStatus");
const automationForecast = $("#automationForecast");
const startButtonLabel = $("#startButtonLabel");
const metricIdentityValue = $("#metricIdentityValue");
const historyRows = $("#historyRows");
const dnsSyncEnabled = $("#dnsSyncEnabled");
const dnsSyncPanel = $("#dnsSyncPanel");
const advancedSettings = $("#advancedSettings");
const dnsRecordName = $("#dnsRecordName");
const dnsZoneId = $("#dnsZoneId");
const dnsApiToken = $("#dnsApiToken");
const autoDnsSync = $("#autoDnsSync");
const subscriptionUrl = $("#subscriptionUrl");

let requestToken = "";
let customIps = [];
let loadedSubscriptionUrl = "";
let activeFamily = "";
let pollTimer = null;
let lastHistoryResultAt = "";

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("show");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove("show"), 2800);
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

function selectedMode() {
  return currentValue("mode") || "asia";
}

function currentPurpose() {
  return argoValidationEnabled.checked ? "argo" : "direct";
}

function sourceIsCustom() {
  return currentValue("ipSource") === "custom";
}

function setCustomStatus(message, kind = "") {
  ipSourceStatus.textContent = message;
  ipSourceStatus.className = `source-status ${kind}`.trim();
}

function updateArgoValidation() {
  const enabled = argoValidationEnabled.checked;
  argoValidationPanel.hidden = !enabled;
  targetHost.required = enabled;
  metricIdentityValue.textContent = enabled ? "我的 Argo 域名（高级复核）" : "speed.cloudflare.com";
}

function updateSourcePanel() {
  customSourcePanel.hidden = !sourceIsCustom();
  if (!sourceIsCustom()) {
    customIps = [];
    loadedSubscriptionUrl = "";
    setCustomStatus("使用测速端点 DNS 种子 + Cloudflare 官方 CIDR 分散抽样。", "ready");
  }
}

function updateDnsSync() {
  dnsSyncPanel.hidden = !dnsSyncEnabled.checked;
  if (!dnsSyncEnabled.checked) autoDnsSync.checked = false;
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
  return (Math.floor(24 * 60 / minutes) + 1) * perRunMb;
}

function updateAutomationChoice() {
  const enabled = automationEnabled.checked;
  startButtonLabel.textContent = enabled ? "开启定时自动优选" : "开始优选 IP";
  const min = Number(window.rrConfig?.automation?.min_interval_minutes || 5);
  const max = Number(window.rrConfig?.automation?.max_interval_minutes || 1440);
  automationInterval.min = String(min);
  automationInterval.max = String(max);
  const interval = Number.parseInt(automationInterval.value, 10) || min;
  const perRunMb = estimateTrafficMb(selectedMode(), currentValue("family"));
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

function formatMbps(value) {
  return `${Number(value || 0).toFixed(1)} Mbps`;
}

function familyRows(result, familyName) {
  const family = result.families?.find((item) => item.family === familyName);
  if (!family) return [];
  return result.mode === "asia" ? (family.asia_ranked || []) : (family.ranked || []);
}

async function copyText(value, successMessage) {
  try {
    await navigator.clipboard.writeText(value);
    showToast(successMessage);
  } catch {
    showToast("复制失败，请手动复制");
  }
}

function dnsSettings() {
  return {
    record_name: dnsRecordName.value.trim(),
    zone_id: dnsZoneId.value.trim(),
    api_token: dnsApiToken.value.trim(),
  };
}

function validateDnsSettings() {
  const settings = dnsSettings();
  if (!dnsSyncEnabled.checked) throw new Error("请先在高级设置中开启 Cloudflare DNS 同步");
  if (!settings.record_name) throw new Error("请填写完整 DNS 记录名");
  if (!/^[0-9a-fA-F]{32}$/.test(settings.zone_id)) throw new Error("请填写 32 位 Cloudflare Zone ID");
  if (!settings.api_token) throw new Error("请填写 Cloudflare API Token");
  return settings;
}

function revealDnsSettings(focusTarget) {
  advancedSettings.open = true;
  dnsSyncEnabled.checked = true;
  updateDnsSync();
  const target = focusTarget || dnsRecordName;
  target.scrollIntoView({ behavior: "smooth", block: "center" });
  target.focus();
}

async function syncWinner(ip, family) {
  let settings;
  if (!dnsSyncEnabled.checked) {
    dnsSyncEnabled.checked = true;
    updateDnsSync();
  }
  try {
    settings = validateDnsSettings();
  } catch (error) {
    const target = !dnsRecordName.value.trim()
      ? dnsRecordName
      : !/^[0-9a-fA-F]{32}$/.test(dnsZoneId.value.trim())
        ? dnsZoneId
        : dnsApiToken;
    revealDnsSettings(target);
    showToast(error.message);
    return;
  }
  const type = family === "IPv6" ? "AAAA" : "A";
  try {
    const inspected = await request("/api/dns/inspect", { ...settings, ip, family });
    const plan = inspected.plan || {};
    const actionText = plan.action === "create"
      ? `将新建 ${type} 记录：${settings.record_name} → ${ip}\n代理：DNS-only（灰云）\nTTL：自动`
      : plan.action === "update"
        ? `将更新 ${type} 记录：${settings.record_name}\nIP：${plan.previous_content || "（空）"} → ${ip}${plan.previous_proxied === true ? "\n代理：橙云 → DNS-only（灰云）" : "\n代理：保持 DNS-only（灰云）"}${Number(plan.previous_ttl) !== 1 ? `\nTTL：${plan.previous_ttl ?? "未知"} → 自动` : "\nTTL：保持自动"}`
        : `该 ${type} 记录已经是 ${ip}，代理为 DNS-only（灰云），TTL 为自动，无需修改`;
    if (!window.confirm(`Cloudflare DNS 变更预览\n\n${actionText}\n\n只操作这个指定记录，节点 SNI/Host 不受影响。确认执行？`)) return;
    const result = await request("/api/dns/apply", {
      ...settings, ip, family, fingerprint: plan.fingerprint, dns_write_confirmed: true,
    });
    showToast(result.message || `${type} 记录同步成功`);
  } catch (error) {
    showToast(error.message);
  }
}

function renderResult(result) {
  const families = result.families || [];
  if (!families.length) return;
  resultSection.hidden = false;
  const argoVerified = result.purpose === "argo";
  resultKicker.textContent = argoVerified ? "CF IP RANKING · ARGO VERIFIED" : "CLOUDFLARE IP RANKING";
  resultTitle.textContent = "可直接填入节点地址的 IP";
  resultDescription.textContent = argoVerified
    ? "候选已通过你提供的 Argo 域名兼容复核。仍只替换 address / server；节点原端口、SNI、Host 与 Path 保持不变。"
    : "复制 IP 后只替换节点 address / server；节点原端口、SNI、Host、传输协议与 WS Path 保持不变。";
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
    winnerCard.innerHTML = "<div class=\"winner-domain\"><small>NO RESULT</small><h3>没有可完成多轮复核的 IP</h3><p>检查协议栈、网络出口或换用均衡模式后重试。</p></div>";
    resultRows.innerHTML = "";
    return;
  }
  const target = Number(result.target_mbps || 100);
  const meetsTarget = Number(winner.round_floor_mbps || 0) >= target;
  winnerCard.innerHTML = `
    <div class="winner-domain"><small>TOP 01 · ${escapeHtml(activeFamily)}</small><h3>${escapeHtml(winner.ip)}</h3><p>${escapeHtml(winner.pop || "POP 未知")} · ${escapeHtml(winner.stability || "待评估")} · ${Number(winner.rounds_tested || 0)} 轮完整复核</p><div class="winner-actions"><button type="button" class="mini-button primary-copy" data-winner-ip>复制 IP</button><button type="button" class="mini-button" data-winner-dns>解析到我的域名（DNS-only）</button></div></div>
    <div class="winner-stat"><small>复核底线</small><strong>${formatMbps(winner.round_floor_mbps)}</strong><em>任一失败即为 0</em></div>
    <div class="winner-stat"><small>平均速度</small><strong>${formatMbps(winner.avg_complete_mbps)}</strong><em>TTFB ${winner.median_ttfb_ms >= 0 ? `${Number(winner.median_ttfb_ms).toFixed(0)} ms` : "—"}</em></div>
    <div class="winner-stat"><small>目标 ${target} Mbps</small><strong>${meetsTarget ? "已达标" : "未达标"}</strong><em>${Number(winner.success_rate_pct || 0).toFixed(1)}% 成功率</em></div>`;
  resultRows.innerHTML = rows.map((row, index) => {
    const rowMeetsTarget = Number(row.round_floor_mbps || 0) >= target;
    return `<tr><td><div class="rank-domain"><span class="rank-number">${index + 1}</span><div><strong>${escapeHtml(row.ip)}</strong><small>${escapeHtml(row.family)} · ${Number(row.rounds_tested || 0)} 轮 · ${rowMeetsTarget ? "已达标" : "未达标"}</small><div class="row-actions"><button type="button" class="copy-button" data-copy-ip="${escapeHtml(row.ip)}">复制 IP</button></div></div></div></td>
      <td class="speed-cell"><strong>${formatMbps(row.round_floor_mbps)}</strong><small>最低轮次</small></td><td class="speed-cell"><strong>${formatMbps(row.avg_complete_mbps)}</strong><small>最高 ${formatMbps(row.max_complete_mbps)}</small></td>
      <td><span class="quality-pill">${Number(row.success_rate_pct || 0).toFixed(1)}%</span></td><td>${Number(row.variation_pct || 0).toFixed(1)}%</td><td><span class="pop-pill">${escapeHtml(row.pop || "UNKNOWN")}</span><br><small>${escapeHtml(row.loc || "")}</small></td><td class="address-cell">${escapeHtml((row.source_tags || []).join(" / ") || "Cloudflare 官方 IP 池")}</td></tr>`;
  }).join("");
  winnerCard.querySelector("[data-winner-ip]")?.addEventListener("click", () => copyText(winner.ip, "已复制 IP；请只替换节点 address / server"));
  winnerCard.querySelector("[data-winner-dns]")?.addEventListener("click", () => syncWinner(winner.ip, activeFamily));
  resultRows.querySelectorAll("[data-copy-ip]").forEach((button) => button.addEventListener("click", () => copyText(button.dataset.copyIp || "", "已复制 IP")));
}

function historyWinner(entry, family) {
  const rows = entry.mode === "asia" ? (family.asia_ranked || []) : (family.ranked || []);
  return rows[0] || null;
}

async function loadHistory() {
  try {
    const response = await fetch("/api/history", { cache: "no-store" });
    const entries = await response.json();
    if (!Array.isArray(entries) || !entries.length) {
      historyRows.innerHTML = "<p class=\"history-empty\">还没有历史记录。完成第一轮优选后会自动保存在这里。</p>";
      return;
    }
    historyRows.innerHTML = entries.slice(0, 10).map((entry) => {
      const champions = (entry.families || []).map((family) => ({ family: family.family, row: historyWinner(entry, family) })).filter((item) => item.row);
      const date = new Date(entry.created_at || "");
      const created = Number.isNaN(date.getTime()) ? String(entry.created_at || "") : date.toLocaleString();
      const target = Number(entry.target_mbps || 100);
      return `<article class="history-card"><div><small>${escapeHtml(created)}</small><strong>${entry.mode === "asia" ? "亚洲狩猎" : "均衡模式"} · ${escapeHtml(entry.operator || "自动")} · 目标 ${target} Mbps</strong></div><div class="history-champions">${champions.map((item) => `<button type="button" data-history-ip="${escapeHtml(item.row.ip)}"><span>${escapeHtml(item.family)}</span><b>${escapeHtml(item.row.ip)}</b><small>${formatMbps(item.row.round_floor_mbps)} · ${Number(item.row.round_floor_mbps || 0) >= target ? "达标" : "未达标"}</small></button>`).join("") || "<span>本轮无有效冠军</span>"}</div></article>`;
    }).join("");
    historyRows.querySelectorAll("[data-history-ip]").forEach((button) => button.addEventListener("click", () => copyText(button.dataset.historyIp || "", "已复制历史冠军 IP")));
  } catch (error) {
    historyRows.innerHTML = `<p class="history-empty">历史读取失败：${escapeHtml(error.message)}</p>`;
  }
}

function updateStatus(snapshot) {
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
    startButtonLabel.textContent = "开始优选 IP";
  }
  if (snapshot.result) {
    renderResult(snapshot.result);
    if (status === "completed" && snapshot.result.created_at !== lastHistoryResultAt) {
      lastHistoryResultAt = snapshot.result.created_at;
      loadHistory();
    }
  }
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

async function applyParsed(result, sourceName, sourceSubscriptionUrl = "") {
  customIps = result.ips || [];
  loadedSubscriptionUrl = sourceSubscriptionUrl;
  const warnings = (result.warnings || []).join(" · ");
  setCustomStatus(`${sourceName}：识别 ${customIps.length} 个公网 IP${warnings ? ` · ${warnings}` : ""}`, "ready");
  showToast(`已载入 ${customIps.length} 个 IP`);
}

$("#parseIpsButton").addEventListener("click", async () => {
  try {
    await applyParsed(await request("/api/ips/parse", { text: ipInput.value, filename: "paste.txt" }), "已识别粘贴内容");
  } catch (error) {
    setCustomStatus(error.message, "error");
  }
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
  try {
    await applyParsed(await request("/api/ips/parse", { text: await file.text(), filename: file.name }), `已导入 ${file.name}`);
  } catch (error) {
    setCustomStatus(error.message, "error");
  }
  ipFile.value = "";
});

$("#fetchSubscriptionButton").addEventListener("click", async () => {
  const url = subscriptionUrl.value.trim();
  try {
    const result = await request("/api/ips/fetch", { url });
    await applyParsed(result, `已读取 ${result.final_url || "订阅"}`, result.final_url || url);
  } catch (error) {
    setCustomStatus(error.message, "error");
  }
});

ipInput.addEventListener("input", () => {
  if (!customIps.length || loadedSubscriptionUrl) return;
  customIps = [];
  setCustomStatus("粘贴内容已改变，请重新点击“识别输入”", "error");
});
subscriptionUrl.addEventListener("input", () => {
  if (!loadedSubscriptionUrl) return;
  loadedSubscriptionUrl = "";
  customIps = [];
  setCustomStatus("订阅链接已改变，请重新读取", "error");
});

form.querySelectorAll("input[name=ipSource]").forEach((input) => input.addEventListener("change", updateSourcePanel));
form.querySelectorAll("input[name=mode]").forEach((input) => input.addEventListener("change", () => { updatePoolHint(window.rrConfig || {}); updateAutomationChoice(); }));
form.querySelectorAll("input[name=family]").forEach((input) => input.addEventListener("change", updateAutomationChoice));
argoValidationEnabled.addEventListener("change", updateArgoValidation);
dnsSyncEnabled.addEventListener("change", updateDnsSync);
automationEnabled.addEventListener("change", updateAutomationChoice);
automationInterval.addEventListener("change", () => {
  const min = Number(window.rrConfig?.automation?.min_interval_minutes || 5);
  const max = Number(window.rrConfig?.automation?.max_interval_minutes || 1440);
  const parsed = Number.parseInt(automationInterval.value, 10);
  automationInterval.value = String(Number.isFinite(parsed) ? Math.max(min, Math.min(max, parsed)) : min);
  localStorage.setItem("rr-edge-hunter-interval-minutes", automationInterval.value);
  updateAutomationChoice();
});

for (const [element, key] of [[dnsRecordName, "rr-edge-hunter-dns-record"], [dnsZoneId, "rr-edge-hunter-zone-id"]]) {
  element.addEventListener("change", () => localStorage.setItem(key, element.value.trim()));
}

$("#refreshHistoryButton").addEventListener("click", loadHistory);

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (sourceIsCustom() && !customIps.length) {
    setCustomStatus("请先识别、导入或读取 IP 名单", "error");
    return;
  }
  const parsedTarget = Number.parseInt(targetMbps.value, 10);
  const minTarget = Number(window.rrConfig?.target_mbps?.min || 1);
  const maxTarget = Number(window.rrConfig?.target_mbps?.max || 10000);
  if (!Number.isFinite(parsedTarget) || parsedTarget < minTarget || parsedTarget > maxTarget) {
    showToast(`目标带宽必须在 ${minTarget}–${maxTarget} Mbps 之间`);
    return;
  }
  const argo = currentPurpose() === "argo";
  const payload = {
    mode: currentValue("mode"),
    family: currentValue("family"),
    operator: currentValue("operator"),
    purpose: argo ? "argo" : "direct",
    target_host: argo ? targetHost.value.trim() : "",
    node_port: argo ? Number.parseInt(nodePort.value, 10) : 443,
    ws_path: argo ? wsPath.value.trim() : "",
    target_mbps: parsedTarget,
    source: sourceIsCustom() ? "custom" : "dns",
    ips: customIps,
    subscription_url: sourceIsCustom() ? loadedSubscriptionUrl : "",
    confirmed: true,
  };
  const automated = automationEnabled.checked;
  if (automated) payload.interval_minutes = Number.parseInt(automationInterval.value, 10);
  if (automated && autoDnsSync.checked) {
    try {
      payload.dns_sync = { ...validateDnsSettings(), enabled: true };
    } catch (error) {
      showToast(error.message);
      return;
    }
  }
  const perRunMb = estimateTrafficMb(payload.mode, payload.family);
  const estimate = formatDataAmountMb(perRunMb);
  const confirmation = automated
    ? `将立即开始，并在每轮完成后等待 ${payload.interval_minutes} 分钟再重测。每轮最高计划流量约 ${estimate}；按此间隔的理论 24 小时上限约 ${formatDataAmountMb(automationDailyUpperBoundMb(payload.interval_minutes, perRunMb))}。是否开启？`
    : `本轮会进行真实 HTTPS 下载，最高计划流量约 ${estimate}。是否开始？`;
  if (!window.confirm(confirmation)) return;
  if (payload.dns_sync) {
    if (!window.confirm(`定时同步二次确认：每轮优选成功后，将冠军 IPv4/IPv6 写入 ${payload.dns_sync.record_name} 的 A/AAAA 记录，并强制 DNS-only。是否授权？`)) return;
    payload.dns_write_confirmed = true;
  }
  try {
    const result = await request(automated ? "/api/automation/start" : "/api/start", payload);
    showToast(result.message || (automated ? "定时自动优选已开启" : "优选已开始"));
    ensurePolling();
    await poll();
  } catch (error) {
    showToast(error.message);
  }
});

stopButton.addEventListener("click", async () => {
  try {
    showToast((await request("/api/stop", {})).message);
    automationEnabled.checked = false;
    updateAutomationChoice();
  } catch (error) {
    showToast(error.message);
  }
});

(async () => {
  try {
    const config = await (await fetch("/api/config", { cache: "no-store" })).json();
    window.rrConfig = config;
    requestToken = config.request_token || "";
    nodePort.value = String(config.default_node_port || 443);
    targetMbps.min = String(config.target_mbps?.min || 1);
    targetMbps.max = String(config.target_mbps?.max || 10000);
    targetMbps.value = String(config.target_mbps?.default || 100);
    const savedInterval = Number.parseInt(localStorage.getItem("rr-edge-hunter-interval-minutes") || "", 10);
    if (Number.isFinite(savedInterval)) automationInterval.value = String(savedInterval);
    dnsRecordName.value = localStorage.getItem("rr-edge-hunter-dns-record") || "";
    dnsZoneId.value = localStorage.getItem("rr-edge-hunter-zone-id") || "";
    if (dnsRecordName.value || dnsZoneId.value) dnsSyncEnabled.checked = true;
    $("#versionLabel").textContent = `Desktop ${config.version || ""}`;
    updatePoolHint(config);
    updateArgoValidation();
    updateSourcePanel();
    updateDnsSync();
    updateAutomationChoice();
    ensurePolling();
    await Promise.all([poll(), loadHistory()]);
  } catch (error) {
    errorBox.hidden = false;
    errorBox.textContent = `初始化失败：${error.message}`;
  }
})();
