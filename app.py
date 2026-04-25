from flask import Flask, render_template, request
import pickle
import pandas as pd
from urllib.parse import urlparse

from feature_extraction import extract_features

app = Flask(__name__)

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


@app.route("/", methods=["GET", "POST"])
def home():

    result = ""
    result_type = ""
    probability = None

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if not url:
            result = "Please enter a URL."
            result_type = "invalid"
            return render_template("index.html", result=result, result_type=result_type, probability=probability)

        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        if not is_valid_url_format(url):
            result = "Invalid entry. Please enter a valid URL like https://example.com"
            result_type = "invalid"
            return render_template("index.html", result=result, result_type=result_type, probability=probability)

        features = extract_features(url)
        status = features.get("_status")

        if status == "dns_fail":
            result = "This website does not exist. The domain could not be resolved."
            result_type = "not_exist"
            return render_template("index.html", result=result, result_type=result_type, probability=probability)

        if status == "fetch_fail":
            result = "Website exists but the page could not be loaded."
            result_type = "not_exist"
            return render_template("index.html", result=result, result_type=result_type, probability=probability)

        if status == "invalid_url":
            result = "Invalid entry. Please enter a valid URL."
            result_type = "invalid"
            return render_template("index.html", result=result, result_type=result_type, probability=probability)

        try:
            row = {col: features.get(col, 1) for col in FEATURE_COLUMNS}
            df = pd.DataFrame([row], columns=FEATURE_COLUMNS)

            prediction = model.predict(df)[0]
            proba = model.predict_proba(df)[0]

            classes = list(model.classes_)
            phish_prob = proba[classes.index(-1)] if -1 in classes else proba[0]
            probability = round(phish_prob * 100, 1)

            if prediction == -1:
                result = "Phishing Website"
                result_type = "phishing"
            else:
                result = "Legitimate Website"
                result_type = "legitimate"

        except Exception as e:
            result = f"Prediction error: {str(e)}"
            result_type = "error"

    return render_template("index.html", result=result, result_type=result_type, probability=probability)


if __name__ == "__main__":
    app.run(debug=True, port=5050)
