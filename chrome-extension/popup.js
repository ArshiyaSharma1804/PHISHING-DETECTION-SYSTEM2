const analyzeBtn = document.getElementById("analyzeBtn");
const currentUrlBox = document.getElementById("currentUrl");
const resultBox = document.getElementById("result");
const verdictEl = document.getElementById("verdict");
const subMessageEl = document.getElementById("subMessage");
const dividerEl = document.getElementById("divider");
const probRow = document.getElementById("probRow");
const probValue = document.getElementById("probValue");
const probBarBg = document.getElementById("probBarBg");
const probBarFill = document.getElementById("probBarFill");
const scanning = document.getElementById("scanning");

let currentUrl = "";

// Get the current tab URL
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  currentUrl = tabs[0].url;
  currentUrlBox.textContent = currentUrl;
});

analyzeBtn.addEventListener("click", async () => {
  if (!currentUrl) return;

  // Show scanning state
  analyzeBtn.disabled = true;
  analyzeBtn.textContent = "SCANNING...";
  resultBox.style.display = "none";
  scanning.style.display = "block";

  try {
    const response = await fetch("http://127.0.0.1:5050/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: currentUrl })
    });

    const data = await response.json();

    // Hide scanning
    scanning.style.display = "none";
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = "ANALYZE";

    // Show result box
    resultBox.style.display = "block";
    resultBox.className = "result " + data.status;
    verdictEl.className = "verdict " + data.status;

    // Set verdict text
    if (data.status === "phishing") {
      verdictEl.textContent = "Phishing";
    } else if (data.status === "legitimate") {
      verdictEl.textContent = "Legitimate";
    } else if (data.status === "not_exist") {
      verdictEl.textContent = "Does Not Exist";
    } else if (data.status === "invalid") {
      verdictEl.textContent = "Invalid URL";
    } else {
      verdictEl.textContent = "Error";
    }

    // Sub message
    subMessageEl.textContent = data.message || "";

    // Show probability bar only for phishing/legitimate
    if (data.status === "phishing" || data.status === "legitimate") {
      const prob = data.probability || 0;
      dividerEl.style.display = "block";
      probRow.style.display = "flex";
      probBarBg.style.display = "block";

      probValue.textContent = prob + "%";
      probValue.style.color = prob > 70 ? "#e05555" : prob > 40 ? "#d4a017" : "#4caf50";

      probBarFill.style.width = prob + "%";
      probBarFill.style.background = prob > 70 ? "#e05555" : prob > 40 ? "#d4a017" : "#4caf50";
    } else {
      dividerEl.style.display = "none";
      probRow.style.display = "none";
      probBarBg.style.display = "none";
    }

  } catch (err) {
    scanning.style.display = "none";
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
