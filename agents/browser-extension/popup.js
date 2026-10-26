document.addEventListener("DOMContentLoaded", async () => {
  const statusEl = document.getElementById("shield-status");
  const countEl = document.getElementById("threats-count");
  const domainEl = document.getElementById("current-domain");
  const toggleBtn = document.getElementById("toggle-shield");

  // Load storage state
  const data = await chrome.storage.local.get(["protectionEnabled", "threatsBlocked"]);
  const enabled = data.protectionEnabled !== false;
  statusEl.textContent = enabled ? "ACTIVE" : "PAUSED";
  statusEl.style.color = enabled ? "#43f0a2" : "#f6b94a";
  countEl.textContent = data.threatsBlocked || 0;

  // Query active tab domain
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      domainEl.textContent = new URL(tab.url).hostname || "Internal Tab";
    }
  } catch (e) {
    domainEl.textContent = "Protected Tab";
  }

  toggleBtn.addEventListener("click", async () => {
    const updated = !enabled;
    await chrome.storage.local.set({ protectionEnabled: updated });
    statusEl.textContent = updated ? "ACTIVE" : "PAUSED";
    statusEl.style.color = updated ? "#43f0a2" : "#f6b94a";
  });
});
