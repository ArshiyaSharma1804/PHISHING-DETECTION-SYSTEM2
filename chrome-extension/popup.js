const currentUrlBox = document.getElementById("currentUrl");
const analyzeBtn = document.getElementById("analyzeBtn");
const resultBox = document.getElementById("result");
const verdictEl = document.getElementById("verdict");
const subMessageEl = document.getElementById("subMessage");
const dividerEl = document.getElementById("divider");
const probRow = document.getElementById("probRow");
const probValue = document.getElementById("probValue");
const probBarBg = document.getElementById("probBarBg");
const probBarFill = document.getElementById("probBarFill");

let currentUrl = "";

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  currentUrl = tabs[0].url;
  currentUrlBox.textContent = currentUrl;
});

function showBlockScreen(url, probability) {
  // Clear body
  document.body.innerHTML = "";
  document.body.style.cssText = "width:320px;background:#0f0f0f;font-family:'IBM Plex Mono',monospace;padding:24px;box-sizing:border-box;margin:0;";

  // Warning icon
  const icon = document.createElement("div");
  icon.textContent = "⚠️";
  icon.style.cssText = "width:60px;height:60px;border-radius:50%;background:#1a0000;border:2px solid #e05555;display:flex;align-items:center;justify-content:center;font-size:28px;margin:0 auto 16px;";
  document.body.appendChild(icon);

  // Title
  const title = document.createElement("div");
  title.textContent = "PHISHING DETECTED";
  title.style.cssText = "font-size:20px;font-weight:700;color:#e05555;text-align:center;margin-bottom:6px;letter-spacing:-0.5px;";
  document.body.appendChild(title);

  // URL
  const urlDiv = document.createElement("div");
  urlDiv.textContent = url;
  urlDiv.style.cssText = "font-size:11px;color:#555;text-align:center;margin-bottom:20px;word-break:break-all;line-height:1.6;";
  document.body.appendChild(urlDiv);

  // Probability box
  const probBox = document.createElement("div");
  probBox.style.cssText = "background:#1a0a0a;border:1px solid #3d1a1a;border-radius:8px;padding:14px;margin-bottom:20px;";

  const probLabel = document.createElement("div");
  probLabel.textContent = "PHISHING PROBABILITY";
  probLabel.style.cssText = "font-size:10px;color:#555;letter-spacing:2px;margin-bottom:6px;";
  probBox.appendChild(probLabel);

  const probNum = document.createElement("div");
  probNum.textContent = probability + "%";
  probNum.style.cssText = "font-size:28px;font-weight:700;color:#e05555;";
  probBox.appendChild(probNum);

  const barBg = document.createElement("div");
  barBg.style.cssText = "height:4px;background:#1a1a1a;border-radius:2px;margin-top:8px;overflow:hidden;";
  const barFill = document.createElement("div");
  barFill.style.cssText = "height:100%;background:#e05555;border-radius:2px;width:" + probability + "%;";
  barBg.appendChild(barFill);
  probBox.appendChild(barBg);
  document.body.appendChild(probBox);

  // Warning message
  const msg = document.createElement("div");
  msg.textContent = "This website may steal your personal data.";
  msg.style.cssText = "font-size:11px;color:#555;text-align:center;margin-bottom:16px;line-height:1.7;";
  document.body.appendChild(msg);

  // Leave button
  const leaveBtn = document.createElement("button");
  leaveBtn.textContent = "LEAVE THIS SITE";
  leaveBtn.style.cssText = "width:100%;padding:12px;background:#e05555;color:white;border:none;border-radius:6px;cursor:pointer;font-family:'IBM Plex Mono',monospace;font-size:12px;font-weight:600;letter-spacing:1px;margin-bottom:8px;display:block;";
  leaveBtn.addEventListener("click", () => {
    chrome.tabs.update({ url: "chrome://newtab" });
  });
  document.body.appendChild(leaveBtn);

  // Dismiss button
  const dismissBtn = document.createElement("button");
  dismissBtn.textContent = "Dismiss";
  dismissBtn.style.cssText = "width:100%;padding:10px;background:transparent;color:#444;border:1px solid #222;border-radius:6px;cursor:pointer;font-family:'IBM Plex Mono',monospace;font-size:11px;display:block;";
  dismissBtn.addEventListener("click", () => {
    window.close();
  });
  document.body.appendChild(dismissBtn);
}

analyzeBtn.addEventListener("click", async () => {
  if (!currentUrl) return;
  analyzeBtn.disabled = true;
  analyzeBtn.textContent = "SCANNING...";
  resultBox.style.display = "none";

  try {
    const response = await fetch("http://127.0.0.1:5050/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: currentUrl })
    });

    const data = await response.json();
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = "ANALYZE";

    if (data.status === "phishing") {
      showBlockScreen(currentUrl, data.probability || 0);
      return;
    }

    resultBox.style.display = "block";
    resultBox.className = "result " + data.status;
    verdictEl.className = "verdict " + data.status;

    if (data.status === "legitimate") verdictEl.textContent = "Legitimate";
    else if (data.status === "not_exist") verdictEl.textContent = "Does Not Exist";
    else if (data.status === "invalid") verdictEl.textContent = "Invalid URL";
    else verdictEl.textContent = "Error";

    subMessageEl.textContent = data.message || "";

    if (data.status === "legitimate") {
      const prob = data.probability || 0;
      dividerEl.style.display = "block";
      probRow.style.display = "flex";
      probBarBg.style.display = "block";
      probValue.textContent = prob + "%";
      probValue.style.color = "#4caf50";
      probBarFill.style.width = prob + "%";
      probBarFill.style.background = "#4caf50";
    } else {
      dividerEl.style.display = "none";
      probRow.style.display = "none";
      probBarBg.style.display = "none";
    }

  } catch (err) {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = "ANALYZE";
    resultBox.style.display = "block";
    resultBox.className = "result error";
    verdictEl.className = "verdict error";
    verdictEl.textContent = "Error";
    subMessageEl.textContent = "Could not connect to Flask app. Make sure it is running on port 5050.";
    dividerEl.style.display = "none";
    probRow.style.display = "none";
    probBarBg.style.display = "none";
  }
});
