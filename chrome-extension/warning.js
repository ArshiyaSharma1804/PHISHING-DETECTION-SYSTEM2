// elements
const body = document.getElementById("bodyState");
const stateIcon = document.getElementById("stateIcon");
const spinner = document.getElementById("spinner");
const title = document.getElementById("title");
const urlDisplay = document.getElementById("urlDisplay");
const probLabel = document.getElementById("probLabel");
const probValue = document.getElementById("probValue");
const probBarFill = document.getElementById("probBarFill");
const description = document.getElementById("description");

const btnBlock = document.getElementById("btnBlock");
const btnProceed = document.getElementById("btnProceed");
const btnGoBack = document.getElementById("btnGoBack");

const glow1 = document.getElementById("glow1");
const glow2 = document.getElementById("glow2");

// Get URL parameters
const urlParams = new URLSearchParams(window.location.search);
const targetUrl = urlParams.get("url");

if (!targetUrl) {
  showError("No URL provided to analyze.");
} else {
  urlDisplay.textContent = targetUrl;
  performScan(targetUrl);
}

// Perform scan by calling the backend Flask API
async function performScan(url) {
  try {
    const response = await fetch("http://127.0.0.1:5050/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
      throw new Error(`Server returned status ${response.status}`);
    }

    const data = await response.json();
    handleScanResult(data);
  } catch (err) {
    console.error("Scan failed: ", err);
    showOfflineWarning();
  }
}

// Handle legitimate vs phishing results
function handleScanResult(data) {
  // Hide spinner
  spinner.classList.add("hidden");

  const probability = data.probability !== undefined ? data.probability : 0;

  // Cache result for popup and set action badge in background
  chrome.tabs.getCurrent((tab) => {
    if (tab) {
      chrome.storage.local.set({
        [`result_${tab.id}`]: {
          url: targetUrl,
          status: data.status,
          probability: probability,
          message: data.message || ""
        }
      });

      if (data.status === "phishing") {
        chrome.action.setBadgeText({ text: "!", tabId: tab.id });
        chrome.action.setBadgeBackgroundColor({ color: "#e05555", tabId: tab.id });
      } else {
        chrome.action.setBadgeText({ text: "", tabId: tab.id });
      }
    }
  });

  if (data.status === "phishing") {
    // ── PHISHING DETECTED ──
    body.className = "state-phishing";
    stateIcon.textContent = "⚠️";
    title.textContent = "PHISHING DETECTED";

    probLabel.textContent = "PHISHING PROBABILITY";
    probValue.textContent = `${probability}%`;
    probBarFill.style.width = `${probability}%`;

    description.textContent = "PhishGuard has blocked this page. It has been flagged as a phishing threat. Proceeding may compromise your personal data, credentials, and financial information.";

    // Change background glow to dark red
    glow1.style.background = "#991b1b";
    glow2.style.background = "#7f1d1d";

    // Show button to block/close tab
    btnBlock.classList.remove("hidden");
    btnBlock.textContent = "Close Dangerous Tab";
    btnBlock.onclick = closeTab;

    btnGoBack.classList.remove("hidden");
    btnGoBack.textContent = "Go Back";
    btnGoBack.onclick = goBack;

  } else {
    // ── SAFE/LEGITIMATE WEBSITE ──
    body.className = "state-legitimate";
    stateIcon.textContent = "⛉";
    title.textContent = "Safety Check Complete";

    probLabel.textContent = "PHISHING PROBABILITY";
    probValue.textContent = `${probability}%`;
    probBarFill.style.width = `${probability}%`;

    description.textContent = `This website is analyzed and appears to be safe (phishing probability of only ${probability}%). You were redirected here, but you can proceed normally if you trust this link.`;

    // Change background glow to green
    glow1.style.background = "#064e3b";
    glow2.style.background = "#065f46";

    // Show proceed and back buttons
    btnProceed.classList.remove("hidden");
    btnProceed.textContent = "Proceed to Website";
    btnProceed.onclick = () => proceedAnyway(targetUrl);

    btnGoBack.classList.remove("hidden");
    btnGoBack.textContent = "Close Tab";
    btnGoBack.onclick = closeTab;
  }
}

// Display error/offline state
function showOfflineWarning() {
  spinner.classList.add("hidden");
  body.className = "state-error";
  stateIcon.textContent = "📡";
  title.textContent = "Offline Warning";

  probLabel.textContent = "SECURITY SCAN STATUS";
  probValue.textContent = "UNAVAILABLE";
  probBarFill.style.width = "100%";

  description.textContent = "Could not connect to the PhishGuard analysis server. The Flask backend is offline. We cannot automatically check this site's safety. Please proceed only if you are confident this URL is secure.";

  // Change background glow to dark amber/gray
  glow1.style.background = "#78350f";
  glow2.style.background = "#27272a";

  // Allow proceeding since scanner is offline
  btnProceed.classList.remove("hidden");
  btnProceed.textContent = "Proceed Anyway (Unverified)";
  btnProceed.onclick = () => proceedAnyway(targetUrl);

  btnBlock.classList.remove("hidden");
  btnBlock.textContent = "Close Tab";
  btnBlock.onclick = closeTab;
}

// Display simple UI error
function showError(msg) {
  spinner.classList.add("hidden");
  body.className = "state-error";
  stateIcon.textContent = "❌";
  title.textContent = "Error";
  description.textContent = msg;
  btnBlock.classList.remove("hidden");
  btnBlock.textContent = "Close Tab";
  btnBlock.onclick = closeTab;
}

// Helper to extract domain from a URL
function getDomain(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch (e) {
    return "";
  }
}

// Action helper: Whitelist the URL domain and navigate the tab
function proceedAnyway(url) {
  const domain = getDomain(url);
  if (!domain) {
    window.location.href = url;
    return;
  }

  // Save to whitelist in local storage
  chrome.storage.local.get({ whitelist: [] }, (result) => {
    const whitelist = result.whitelist;
    if (!whitelist.includes(domain)) {
      whitelist.push(domain);
    }
    chrome.storage.local.set({ whitelist: whitelist }, () => {
      // Once whitelisted, navigate this tab back to the target URL
      window.location.href = url;
    });
  });
}

// Action helper: Close current tab
function closeTab() {
  chrome.tabs.getCurrent((tab) => {
    if (tab) {
      chrome.tabs.remove(tab.id);
    } else {
      window.close();
    }
  });
}

// Action helper: Go back in history
function goBack() {
  history.back();
  // Fallback to close tab if history is empty
  setTimeout(closeTab, 300);
}
