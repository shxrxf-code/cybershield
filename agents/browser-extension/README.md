# CyberShield Browser Guard Extension (Manifest V3)

Cross-browser security extension for Google Chrome, Microsoft Edge, Mozilla Firefox, and Chromium-based browsers.

## Capabilities (Module F)
- **Real-Time URL Reputation**: Queries CyberShield `/api/v1/browser/check-url` on navigation.
- **Phishing & Brand Impersonation**: Intercepts credential-harvesting subdomains and homograph attacks.
- **Insecure Form Protection**: Injects in-page warning banner when password fields are rendered on unencrypted HTTP.
- **Dangerous Download Pre-Scan**: Evaluates double-extension payloads and suspicious executable downloads.
- **Zero Data Privacy Intrusion**: Operates on domain & URL metadata without inspecting personal keystrokes or private message bodies.

## Installation Instructions

### Google Chrome & Microsoft Edge
1. Open `chrome://extensions` or `edge://extensions`.
2. Toggle on **Developer mode** in the top-right corner.
3. Click **Load unpacked**.
4. Select the `agents/browser-extension` folder.
5. The **CyberShield Browser Guard** badge will appear in your browser toolbar.

### Mozilla Firefox
1. Open `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on...**.
3. Select `agents/browser-extension/manifest.json`.
