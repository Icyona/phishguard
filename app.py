from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import joblib
import re
from urllib.parse import urlparse

app = Flask(__name__)

# Allow the frontend to communicate with the API
CORS(app, resources={
    r"/predict": {"origins": "*"}
})

# Load trained model
model = joblib.load("phishing_model.pkl")
feature_columns = joblib.load("feature_columns.pkl")


def extract_features(url):

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    features = {}

    features["url_length"] = len(url)
    features["dots"] = url.count(".")
    features["hyphens"] = url.count("-")
    features["digits"] = sum(c.isdigit() for c in url)
    features["slashes"] = url.count("/")
    features["https"] = 1 if parsed.scheme == "https" else 0
    features["at_symbol"] = 1 if "@" in url else 0

    hostname = parsed.hostname or ""

    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    features["ip_address"] = 1 if re.match(ip_pattern, hostname) else 0

    parts = hostname.split(".")
    features["subdomains"] = max(0, len(parts) - 2)

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "signin",
        "bank"
    ]

    features["suspicious_words"] = sum(
        1 for word in suspicious_words if word in url.lower()
    )

    return features


@app.route("/")
def home():
    return jsonify({
        "status": "online",
        "service": "PhishGuard API"
    })


@app.route("/predict", methods=["POST"])
def predict():

    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data["url"]

    features = extract_features(url)

    input_data = pd.DataFrame(
        [[features[col] for col in feature_columns]],
        columns=feature_columns
    )

    prediction = model.predict(input_data)[0]
    probabilities = model.predict_proba(input_data)[0]

    confidence = round(float(max(probabilities)) * 100, 2)

    phishing_probability = float(probabilities[1])

    if phishing_probability >= 0.75:
        classification = "Phishing"
        risk_level = "High"

    elif phishing_probability >= 0.40:
        classification = "Suspicious"
        risk_level = "Medium"

    else:
        classification = "Legitimate"
        risk_level = "Low"

    return jsonify({
        "url": url,
        "classification": classification,
        "risk_level": risk_level,
        "confidence": confidence,
        "features": features
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
