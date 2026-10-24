// SENTINEL X Browser Extension - Background Service Worker
const API_BASE = 'http://localhost:8000/api/v1';

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const url = details.url;
  if (url.startsWith('chrome://') || url.startsWith('about:') || url.startsWith('edge://')) return;
  
  try {
    const response = await fetch(`${API_BASE}/url/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const result = await response.json();
    if (result.blocked || result.action === 'block') {
      chrome.tabs.update(details.tabId, { url: chrome.runtime.getURL('blocked.html') + '?url=' + encodeURIComponent(url) });
    }
  } catch (e) {
    console.error('SENTINEL X: URL check failed', e);
  }
});

console.log('SENTINEL X URL Protection active');
