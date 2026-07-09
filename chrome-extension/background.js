// Helper to extract domain from a URL
function getDomain(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch (e) {
    return "";
  }
}

// Helper to check if domain is trusted
function isTrustedDomain(domain) {
  if (!domain) return false;
  const TRUSTED_DOMAINS = [
    "whatsapp.com",
    "whatsapp.net",
    "google.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "netflix.com",
    "amazon.com",
    "gmail.com",
    "yahoo.com",
    "bing.com",
    "wikipedia.org",
    "live.com",
    "outlook.com"
  ];
  return TRUSTED_DOMAINS.some(trusted => domain === trusted || domain.endsWith("." + trusted));
}

// Listen for tab updates to intercept loading URLs
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Only trigger when a URL starts loading
  if (changeInfo.status !== "loading") return;
  if (!tab.url) return;

  const url = tab.url;

  // Ignore internal/localhost pages to prevent infinite loops and scanning internal resources
  if (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("http://127.0.0.1") ||
    url.startsWith("https://127.0.0.1") ||
    url.startsWith("http://localhost") ||
    url.startsWith("https://localhost") ||
    url === "about:blank" ||
    url.startsWith("about:")
  ) {
    return;
  }

  try {
    const domain = getDomain(url);
    if (!domain) return;

    // Check if the domain is a trusted built-in domain
    if (isTrustedDomain(domain)) {
      console.log(`PhishGuard: Domain ${domain} is a trusted built-in domain. Bypassing check.`);
      return;
    }

    // Check if the domain is whitelisted
    const result = await chrome.storage.local.get({ whitelist: [] });
    const whitelist = result.whitelist;

    if (whitelist.includes(domain)) {
      console.log(`PhishGuard: Domain ${domain} is whitelisted. Bypassing check.`);
      return;
    }

    // Set checking status in local storage for popup visibility
    await chrome.storage.local.set({ [`checking_${tabId}`]: url });

    // Redirect the tab to warning.html
    const warningUrl = chrome.runtime.getURL("warning.html") + "?url=" + encodeURIComponent(url);
    chrome.tabs.update(tabId, { url: warningUrl });
    console.log(`PhishGuard: Redirecting ${url} to warning page.`);

  } catch (err) {
    console.error("PhishGuard background error:", err);
  }
});
