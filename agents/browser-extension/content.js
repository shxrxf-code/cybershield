// CyberShield Browser Guard - Content Script
(function () {
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  const isHttps = window.location.protocol === 'https:';
  const hostname = window.location.hostname;

  // Insecure password transmission warning
  if (passwordInputs.length > 0 && !isHttps) {
    showCyberShieldBanner(
      "SECURITY WARNING: INSECURE LOGIN DETECTED",
      "This webpage contains a password input over an unencrypted HTTP connection. Your credentials can be intercepted.",
      "critical"
    );
  }

  // Check IDN / Punycode homograph attack
  if (hostname.includes("xn--")) {
    showCyberShieldBanner(
      "HOMOGRAPH ATTACK ALERT",
      `The website domain '${hostname}' uses internationalized Cyrillic/Punycode characters which may visually spoof a legitimate domain.`,
      "warning"
    );
  }

  function showCyberShieldBanner(title, message, severity) {
    if (document.getElementById("cybershield-security-banner")) return;

    const banner = document.createElement("div");
    banner.id = "cybershield-security-banner";
    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 2147483647;
      background: ${severity === 'critical' ? '#dc2626' : '#d97706'};
      color: #ffffff;
      padding: 12px 20px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      box-shadow: 0 4px 12px rgba(0,0,0,0.5);
      display: flex;
      align-items: center;
      justify-content: space-between;
    `;

    banner.innerHTML = `
      <div style="display: flex; align-items: center; gap: 12px;">
        <span style="font-weight: 800; font-size: 14px; letter-spacing: 0.05em; background: rgba(0,0,0,0.3); padding: 4px 8px; border-radius: 4px;">CYBERSHIELD</span>
        <div>
          <div style="font-weight: bold; font-size: 13px;">${title}</div>
          <div style="font-size: 12px; opacity: 0.95;">${message}</div>
        </div>
      </div>
      <button id="cybershield-banner-dismiss" style="background: rgba(255,255,255,0.2); border: none; color: white; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: bold;">
        Dismiss Warning
      </button>
    `;

    document.body.prepend(banner);
    document.getElementById("cybershield-banner-dismiss").addEventListener("click", () => {
      banner.remove();
    });
  }
})();
