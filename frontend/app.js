const state = { needsBootstrap: false, targets: [] };

const $ = (selector) => document.querySelector(selector);
const authView = $("#auth-view");
const dashboardView = $("#dashboard-view");
const authForm = $("#auth-form");
const targetDialog = $("#target-dialog");
const historyDialog = $("#history-dialog");

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (response.status === 204) return null;
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || "Something went wrong. Please try again.");
  return body;
}

function showToast(message, variant = "success") {
  const toast = $("#toast");
  toast.textContent = message;
  toast.className = `toast ${variant}`;
  toast.hidden = false;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => { toast.hidden = true; }, 3600);
}

function setFormError(selector, message = "") {
  const node = $(selector);
  node.textContent = message;
  node.hidden = !message;
}

function formatTime(value) {
  if (!value) return "Not checked yet";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function statusLabel(status) {
  return status === "online" ? "Online" : status === "offline" ? "Offline" : "Unknown";
}

function statusClass(status) {
  return status === "online" ? "online" : status === "offline" ? "offline" : "unknown";
}

function targetCard(target) {
  const status = statusClass(target.latest_status);
  const timing = target.latest_response_ms !== null && target.latest_response_ms !== undefined
    ? `${target.latest_response_ms} ms`
    : target.latest_error || "No result yet";
  return `
    <article class="target-card" data-target-id="${target.id}">
      <div class="target-card-main">
        <div class="target-identity">
          <span class="status-dot ${status}" title="${statusLabel(target.latest_status)}"></span>
          <div><h3>${escapeHtml(target.name)}</h3><p>${escapeHtml(target.host)}:${target.port} · TCP</p></div>
        </div>
        <span class="status-badge ${status}">${statusLabel(target.latest_status)}</span>
      </div>
      <div class="target-metrics">
        <div><span>Response time</span><strong>${escapeHtml(timing)}</strong></div>
        <div><span>Last checked</span><strong>${formatTime(target.latest_checked_at)}</strong></div>
      </div>
      <div class="target-actions">
        <button class="text-button history-action" type="button">View history</button>
        <button class="danger-button delete-action" type="button">Remove</button>
        <button class="secondary-button check-action" type="button">Run check</button>
      </div>
    </article>`;
}

function escapeHtml(value) {
  const textarea = document.createElement("textarea");
  textarea.textContent = String(value ?? "");
  return textarea.innerHTML;
}

function renderDashboard(data) {
  state.targets = data.targets;
  $("#online-count").textContent = data.online_count;
  $("#offline-count").textContent = data.offline_count;
  $("#unknown-count").textContent = data.unknown_count;
  $("#empty-state").hidden = data.targets.length > 0;
  $("#target-list").innerHTML = data.targets.map(targetCard).join("");
}

async function loadDashboard() {
  const refresh = $("#refresh-button");
  refresh.disabled = true;
  refresh.textContent = "Refreshing…";
  try { renderDashboard(await api("/api/dashboard")); }
  catch (error) { showToast(error.message, "error"); }
  finally { refresh.disabled = false; refresh.textContent = "Refresh"; }
}

function showDashboard(user) {
  authView.hidden = true;
  dashboardView.hidden = false;
  $("#user-name").textContent = user.username;
  loadDashboard();
}

function configureAuth(needsBootstrap) {
  state.needsBootstrap = needsBootstrap;
  $("#setup-copy").hidden = !needsBootstrap;
  $("#login-copy").hidden = needsBootstrap;
  $("#password-hint").hidden = !needsBootstrap;
  $("#password").setAttribute("autocomplete", needsBootstrap ? "new-password" : "current-password");
  $("#auth-submit").textContent = needsBootstrap ? "Create secure account" : "Sign in";
}

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setFormError("#auth-error");
  const username = $("#username").value.trim();
  const password = $("#password").value;
  if (!username || !password || (state.needsBootstrap && password.length < 12)) {
    setFormError("#auth-error", state.needsBootstrap ? "Use a username and a password of at least 12 characters." : "Enter your username and password.");
    return;
  }
  const button = $("#auth-submit");
  button.disabled = true;
  button.textContent = state.needsBootstrap ? "Creating account…" : "Signing in…";
  try {
    const user = await api(state.needsBootstrap ? "/api/auth/bootstrap" : "/api/auth/login", { method: "POST", body: JSON.stringify({ username, password }) });
    showDashboard(user);
    showToast(state.needsBootstrap ? "Administrator account created." : "Signed in successfully.");
  } catch (error) {
    setFormError("#auth-error", error.message);
  } finally {
    button.disabled = false;
    button.textContent = state.needsBootstrap ? "Create secure account" : "Sign in";
  }
});

function openTargetDialog() {
  setFormError("#target-error");
  $("#target-form").reset();
  targetDialog.showModal();
  $("#target-form input[name='name']").focus();
}

$("#open-target-form").addEventListener("click", openTargetDialog);
$("#empty-add-target").addEventListener("click", openTargetDialog);
$("#cancel-target").addEventListener("click", () => targetDialog.close());

$("#target-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = { name: form.get("name").trim(), host: form.get("host").trim(), port: Number(form.get("port")) };
  const button = $("#save-target");
  setFormError("#target-error");
  button.disabled = true;
  button.textContent = "Saving…";
  try {
    await api("/api/targets", { method: "POST", body: JSON.stringify(payload) });
    targetDialog.close();
    await loadDashboard();
    showToast("Target added. Run a check when you are ready.");
  } catch (error) {
    setFormError("#target-error", error.message);
  } finally {
    button.disabled = false;
    button.textContent = "Save target";
  }
});

$("#target-list").addEventListener("click", async (event) => {
  const card = event.target.closest("[data-target-id]");
  if (!card) return;
  const targetId = card.dataset.targetId;
  const target = state.targets.find((item) => item.id === Number(targetId));
  if (event.target.closest(".check-action")) {
    const button = event.target.closest("button");
    button.disabled = true; button.textContent = "Checking…";
    try {
      const result = await api(`/api/targets/${targetId}/check`, { method: "POST" });
      await loadDashboard();
      showToast(`${target.name}: ${statusLabel(result.status)}${result.response_ms ? ` in ${result.response_ms} ms` : ""}.`, result.status === "online" ? "success" : "error");
    } catch (error) { showToast(error.message, "error"); }
    finally { button.disabled = false; button.textContent = "Run check"; }
  }
  if (event.target.closest(".delete-action")) {
    if (!window.confirm(`Remove ${target.name}? Its recorded history will also be removed.`)) return;
    try { await api(`/api/targets/${targetId}`, { method: "DELETE" }); await loadDashboard(); showToast("Target removed."); }
    catch (error) { showToast(error.message, "error"); }
  }
  if (event.target.closest(".history-action")) {
    $("#history-title").textContent = `${target.name} history`;
    $("#history-content").innerHTML = "<p class='muted'>Loading history…</p>";
    historyDialog.showModal();
    try {
      const results = await api(`/api/targets/${targetId}/history?limit=25`);
      $("#history-content").innerHTML = results.length ? results.map((result) => `
        <article class="history-row"><span class="status-badge ${statusClass(result.status)}">${statusLabel(result.status)}</span><div><strong>${result.response_ms ? `${result.response_ms} ms` : escapeHtml(result.error_message || "No response time")}</strong><p>${formatTime(result.checked_at)}</p></div></article>`).join("") : "<p class='muted'>No checks have been recorded yet.</p>";
    } catch (error) { $("#history-content").innerHTML = `<p class='form-error'>${escapeHtml(error.message)}</p>`; }
  }
});

$("#close-history").addEventListener("click", () => historyDialog.close());
$("#refresh-button").addEventListener("click", loadDashboard);
$("#logout-button").addEventListener("click", async () => {
  try { await api("/api/auth/logout", { method: "POST" }); } catch (_) { /* Local UI reset is still safe. */ }
  dashboardView.hidden = true; authView.hidden = false; authForm.reset();
  configureAuth((await api("/api/setup-status")).needs_bootstrap);
});

async function initialize() {
  try {
    const setup = await api("/api/setup-status");
    try { showDashboard(await api("/api/auth/me")); }
    catch (_) { configureAuth(setup.needs_bootstrap); }
  } catch (error) { setFormError("#auth-error", `Unable to start: ${error.message}`); }
}

initialize();
