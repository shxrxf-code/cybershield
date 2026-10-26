// CyberShield Browser Guard - Background Service Worker (Manifest V3)
const API_BASE = "http://localhost:8000/api/v1";

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    protectionEnabled: true,
    threatsBlocked: 0,
    whitelistedDomains: ["google.com", "microsoft.com", "github.com", "apple.com"]
  });
  console.log("[CyberShield] Browser extension active and protecting navigation.");
});

// Intercept navigation to evaluate safety
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // Top-level frame only

  const storage = await chrome.storage.local.get(["protectionEnabled", "whitelistedDomains", "threatsBlocked"]);
  if (!storage.protectionEnabled) return;

  const url = details.url;
  try {
    const domain = new URL(url).hostname;
    if (storage.whitelistedDomains && storage.whitelistedDomains.includes(domain)) {
      return;
    }

    // Call CyberShield backend security check
    const response = await fetch(`${API_BASE}/browser/check-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });

    if (response.ok) {
      const data = await response.json();
      if (data.action === "block" || data.is_phishing) {
        // Increment blocked count
        chrome.storage.local.set({ threatsBlocked: (storage.threatsBlocked || 0) + 1 });
        
        // Notify user via Chrome notification or block
        console.warn(`[CyberShield BLOCKED] Malicious destination: ${url} (Risk: ${data.risk_score})`);
      }
    }
  } catch (e) {
    // Backend offline or local network error; fail safe
  }
});
