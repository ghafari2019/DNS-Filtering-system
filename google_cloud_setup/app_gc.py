import os
from flask import Flask, request, jsonify
from prometheus_client import Counter, start_http_server, generate_latest  # Added for Prometheus integration
import joblib
from feature_extraction import extract_features  # Import the feature extraction function

app = Flask(__name__)

# Load the pre-trained XGBoost model
model = joblib.load('best_xgboost_model.joblib')

# Initialize Prometheus metrics
MALICIOUS_URL_COUNTER = Counter('malicious_url_counter_total', 'Count of Malicious URLs Detected')  # Added for Prometheus metric

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json(force=True)
    url = data['url']

    # Extract features
    features = extract_features(url)  # Call the feature extraction function

    # Predict using the model
    prediction = model.predict(features)
    result = {'malicious': bool(prediction)}

    # Increment the Prometheus counter if the URL is malicious
    if prediction:
        MALICIOUS_URL_COUNTER.inc()
        # Log the URL
        app.logger.info(f"Malicious URL detected: {url}")

    return jsonify(result)

if __name__ == '__main__':
    # Start Prometheus client HTTP server on port 8000
    start_http_server(8000)
    # Run Flask application
    app.run(host='0.0.0.0', port=5000)
  