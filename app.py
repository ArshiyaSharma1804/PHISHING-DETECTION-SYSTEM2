from flask import Flask, render_template, request, jsonify
import pickle
import pandas as pd
from urllib.parse import urlparse
from flask_cors import CORS

from feature_extraction import extract_features

app = Flask(__name__)
CORS(app)

with open("model/phishing_model.pkl", "rb") as f:
    model = pickle.load(f)

FEATURE_COLUMNS = [
    "having_IPhaving_IP_Address", "URLURL_Length", "Shortining_Service",
    "having_At_Symbol", "double_slash_redirecting", "Prefix_Suffix",
    "having_Sub_Domain", "SSLfinal_State", "Domain_registeration_length",
    "Favicon", "port", "HTTPS_token", "Request_URL", "URL_of_Anchor",
    "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe",
    "age_of_domain", "DNSRecord", "web_traffic", "Page_Rank",
    "Google_Index", "Links_pointing_to_page", "Statistical_report"
]


def is_valid_url_format(url):
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ["http", "https"]:
        return False
    if not parsed.netloc:
        return False
    host = parsed.netloc.replace("www.", "")
    if "." not in host:
        return False
    tld = host.split(".")[-1]
    if not tld.isalpha() or len(tld) < 2:
        return False
    return True


def run_prediction(url):
    if not url:
        return {"status": "invalid", "message": "No URL provided"}

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    if not is_valid_url_format(url):
        return {"status": "invalid", "message": "Invalid entry. Please enter a valid URL like https://example.com"}

    features = extract_features(url)
    status = features.get("_status")

    if status == "dns_fail":
        return {"status": "not_exist", "message": "This website does not exist. The domain could not be resolved."}

    if status == "fetch_fail":
        return {"status": "not_exist", "message": "Website exists but the page could not be loaded."}

    if status == "invalid_url":
        return {"status": "invalid", "message": "Invalid entry. Please enter a valid URL."}

    try:
        row = {col: features.get(col, 1) for col in FEATURE_COLUMNS}
        df = pd.DataFrame([row], columns=FEATURE_COLUMNS)

        proba = model.predict_proba(df)[0]
        classes = list(model.classes_)
        phish_prob = proba[classes.index(-1)] if -1 in classes else proba[0]
        probability = round(phish_prob * 100, 1)

        # Threshold: below 15% = Legitimate, 15% and above = Phishing
        if phish_prob >= 0.15:
            return {"status": "phishing", "message": "Phishing Website", "probability": probability}
        else:
            return {"status": "legitimate", "message": "Legitimate Website", "probability": probability}

    except Exception as e:
        return {"status": "error", "message": f"Prediction error: {str(e)}"}


# ── Web interface ─────────────────────────────────────────────────────────────
@app.route("/", methods=["GET", "POST"])
def home():
    result = ""
    result_type = ""
    probability = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        data = run_prediction(url)
        result = data.get("message", "")
        result_type = data.get("status", "error")
        probability = data.get("probability", None)

    return render_template(
        "index.html",
        result=result,
        result_type=result_type,
        probability=probability
    )


# ── API endpoint for Chrome extension ────────────────────────────────────────
@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json()
    url = data.get("url", "").strip()
    result = run_prediction(url)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, port=5050)
